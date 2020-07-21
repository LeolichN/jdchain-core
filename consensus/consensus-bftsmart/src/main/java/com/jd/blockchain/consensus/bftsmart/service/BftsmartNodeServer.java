package com.jd.blockchain.consensus.bftsmart.service;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import bftsmart.consensus.app.BatchAppResultImpl;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.*;
import bftsmart.tom.core.messages.TOMMessage;
import com.jd.blockchain.binaryproto.BinaryProtocol;
import com.jd.blockchain.binaryproto.DataContractException;
import com.jd.blockchain.consensus.service.*;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.ledger.*;
import com.jd.blockchain.transaction.TxResponseMessage;
import com.jd.blockchain.utils.ConsoleUtils;
import com.jd.blockchain.utils.StringUtils;
import com.jd.blockchain.utils.serialize.binary.BinarySerializeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.jd.blockchain.consensus.ConsensusManageService;
import com.jd.blockchain.consensus.NodeSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartConsensusProvider;
import com.jd.blockchain.consensus.bftsmart.BftsmartConsensusSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartNodeSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartTopology;
import com.jd.blockchain.utils.PropertiesUtils;
import com.jd.blockchain.utils.concurrent.AsyncFuture;
import com.jd.blockchain.utils.io.BytesUtils;
import bftsmart.reconfiguration.util.HostsConfig;
import bftsmart.reconfiguration.util.TOMConfiguration;
import bftsmart.tom.server.defaultservices.DefaultRecoverable;
import org.springframework.util.NumberUtils;

public class BftsmartNodeServer extends DefaultRecoverable implements NodeServer {

    private static Logger LOGGER = LoggerFactory.getLogger(BftsmartNodeServer.class);

//    private static final String DEFAULT_BINDING_HOST = "0.0.0.0";

    private List<StateHandle> stateHandles = new CopyOnWriteArrayList<>();

    // TODO 暂不处理队列溢出问题
    private ExecutorService notifyReplyExecutors = Executors.newSingleThreadExecutor();

    private volatile Status status = Status.STOPPED;

    private final Object mutex = new Object();

    private volatile ServiceReplica replica;

    private StateMachineReplicate stateMachineReplicate;

    private ServerSettings serverSettings;

    private BftsmartConsensusManageService manageService;


    private volatile BftsmartTopology topology;

    private volatile BftsmartTopology outerTopology;

    private volatile BftsmartConsensusSettings setting;

    private TOMConfiguration tomConfig;

    private TOMConfiguration outerTomConfig;

    private HostsConfig hostsConfig;

    private Properties systemConfig;

    private MessageHandle messageHandle;

    private String providerName;

    private String realmName;

    private int serverId;

    private long latestStateId;

    private View latestView;

    private List<InetSocketAddress> consensusAddresses = new ArrayList<>();

    private final Lock batchHandleLock = new ReentrantLock();

    private volatile InnerStateHolder stateHolder;

    public BftsmartNodeServer() {

    }

    public BftsmartNodeServer(ServerSettings serverSettings, MessageHandle messageHandler, StateMachineReplicate stateMachineReplicate) {
        this.serverSettings = serverSettings;
        this.realmName = serverSettings.getRealmName();
        //used later
        this.stateMachineReplicate = stateMachineReplicate;
        this.latestStateId = stateMachineReplicate.getLatestStateID(realmName);
        this.stateHolder = new InnerStateHolder(latestStateId - 1);
        this.messageHandle = messageHandler;
        createConfig();
        serverId = findServerId();
        initConfig(serverId, systemConfig, hostsConfig);
        this.manageService = new BftsmartConsensusManageService(this);
    }

    protected int findServerId() {
        int serverId = 0;

        String host = ((BftsmartNodeSettings)serverSettings.getReplicaSettings()).getNetworkAddress().getHost();
        int port = ((BftsmartNodeSettings)serverSettings.getReplicaSettings()).getNetworkAddress().getPort();
        for (int i : hostsConfig.getHostsIds()) {

            if (hostsConfig.getHost(i).equals(host) && hostsConfig.getPort(i) == port) {
                serverId = i;
                break;
            }
        }

        return serverId;
    }

    public int getServerId() {
        return serverId;
    }

    protected void createConfig() {

        setting = ((BftsmartServerSettings) serverSettings).getConsensusSettings();

        List<HostsConfig.Config> configList = new ArrayList<>();

        NodeSettings[] nodeSettingsArray = setting.getNodes();
        for (NodeSettings nodeSettings : nodeSettingsArray) {
            BftsmartNodeSettings node = (BftsmartNodeSettings)nodeSettings;
            configList.add(new HostsConfig.Config(node.getId(), node.getNetworkAddress().getHost(), node.getNetworkAddress().getPort()));
            consensusAddresses.add(new InetSocketAddress(node.getNetworkAddress().getHost(), node.getNetworkAddress().getPort()));
        }

        //create HostsConfig instance based on consensus realm nodes
        hostsConfig = new HostsConfig(configList.toArray(new HostsConfig.Config[configList.size()]));

        systemConfig = PropertiesUtils.createProperties(setting.getSystemConfigs());

        return;
    }

    protected void initConfig(int id, Properties systemsConfig, HostsConfig hostConfig) {
        byte[] serialHostConf = BinarySerializeUtils.serialize(hostConfig);
        Properties sysConfClone = (Properties)systemsConfig.clone();
        int port = hostConfig.getPort(id);
//        hostConfig.add(id, DEFAULT_BINDING_HOST, port);

        //if peer-startup.sh set up the -DhostIp=xxx, then get it;
        String preHostPort = System.getProperty("hostPort");
        if(!StringUtils.isEmpty(preHostPort)){
            port = NumberUtils.parseNumber(preHostPort, Integer.class);
            LOGGER.info("###peer-startup.sh###,set up the -DhostPort="+port);
        }

        String preHostIp = System.getProperty("hostIp");
        if(!StringUtils.isEmpty(preHostIp)){
            hostConfig.add(id, preHostIp, port);
            LOGGER.info("###peer-startup.sh###,set up the -DhostIp="+preHostIp);
        }

        this.tomConfig = new TOMConfiguration(id, systemsConfig, hostConfig);

        this.latestView = new View(setting.getViewId(), tomConfig.getInitialView(), tomConfig.getF(), consensusAddresses.toArray(new InetSocketAddress[consensusAddresses.size()]));

        this.outerTomConfig = new TOMConfiguration(id, sysConfClone, BinarySerializeUtils.deserialize(serialHostConf));

    }

    @Override
    public ConsensusManageService getConsensusManageService() {
        return manageService;
    }

    @Override
    public ServerSettings getSettings() {
        return serverSettings;
    }

    @Override
    public String getProviderName() {
        return BftsmartConsensusProvider.NAME;
    }

    // 由于节点动态入网的原因，共识的配置环境是随时可能变化的，需要每次get时从replica动态读取
    public TOMConfiguration getTomConfig() {
       return outerTomConfig;
    }

    public int getId() {
        return tomConfig.getProcessId();
    }

    public void setId(int id) {
        if (id < 0) {
            throw new IllegalArgumentException("ReplicaID is negative!");
        }
        this.tomConfig.setProcessId(id);
        this.outerTomConfig.setProcessId(id);

    }

    // 注意：该方法获得的共识环境为节点启动时从账本里读取的共识环境，如果运行过程中发生了节点动态入网，该环境没有得到更新
    public BftsmartConsensusSettings getConsensusSetting() {
        return setting;
    }

//    public BftsmartTopology getTopology() {
//        if (outerTopology != null) {
//            return outerTopology;
//        }
//        return new BftsmartTopology(replica.getReplicaContext().getCurrentView());
//    }

    public BftsmartTopology getTopology() {
        if (!isRunning()) {
            return null;
        }
        return getOuterTopology();
    }

    private BftsmartTopology getOuterTopology() {
        View currView = this.replica.getReplicaContext().getCurrentView();
        int id = currView.getId();
        int f = currView.getF();
        int[] processes = currView.getProcesses();
        InetSocketAddress[] addresses = new InetSocketAddress[processes.length];
        for (int i = 0; i < processes.length; i++) {
            int pid = processes[i];
            if (id == pid) {
                addresses[i] = new InetSocketAddress(getTomConfig().getHost(id), getTomConfig().getPort(id));
            } else {
                addresses[i] = currView.getAddress(pid);
            }
        }
        View returnView = new View(id, processes, f, addresses);

        for (int i = 0; i < returnView.getProcesses().length; i++) {
            LOGGER.info("[BftsmartNodeServer.getOuterTopology] PartiNode id = {}, host = {}, port = {}", returnView.getProcesses()[i],
                    returnView.getAddress(i).getHostName(), returnView.getAddress(i).getPort());
        }
        this.outerTopology = new BftsmartTopology(returnView);

        return outerTopology;
    }

    public Status getStatus() {
        return status;
    }

    @Override
    public boolean isRunning() {
        return status == Status.RUNNING;
    }

    public byte[] appExecuteUnordered(byte[] bytes, MessageContext messageContext) {
        return messageHandle.processUnordered(bytes).get();
    }

    /**
     *
     *  Only block, no reply， used by state transfer when peer start
     *
     */
    private void block(List<byte[]> manageConsensusCmds) {

        String batchId = messageHandle.beginBatch(realmName);
        try {
            int msgId = 0;
            for (byte[] txContent : manageConsensusCmds) {
                AsyncFuture<byte[]> asyncFuture = messageHandle.processOrdered(msgId++, txContent, realmName, batchId);
            }
            messageHandle.completeBatch(realmName, batchId);
            messageHandle.commitBatch(realmName, batchId);
        } catch (Exception e) {
            // todo 需要处理应答码 404
            LOGGER.error("Error occurred while processing ordered messages! --" + e.getMessage(), e);
            messageHandle.rollbackBatch(realmName, batchId, TransactionState.CONSENSUS_ERROR.CODE);
        }

    }

    /**
     *
     *  Local peer has cid diff with remote peer, used by state transfer when peer start
     *
     */
    private byte[][] appExecuteDiffBatch(byte[][] commands, MessageContext[] msgCtxs) {

        int manageConsensusId = msgCtxs[0].getConsensusId();
        List<byte[]> manageConsensusCmds = new ArrayList<>();

        int index = 0;
        for (MessageContext msgCtx : msgCtxs) {
            if (msgCtx.getConsensusId() == manageConsensusId) {
                manageConsensusCmds.add(commands[index]);
            } else {
                // 达到结块标准，需要进行结块并应答
                block(manageConsensusCmds);
                // 重置链表和共识ID
                manageConsensusCmds = new ArrayList<>();
                manageConsensusId = msgCtx.getConsensusId();
                manageConsensusCmds.add(commands[index]);
            }
            index++;
        }
        // 结束时，肯定有最后一个结块请求未处理
        if (!manageConsensusCmds.isEmpty()) {
            block(manageConsensusCmds);
        }
        return null;

    }

    /**
     *
     *  Invoked by state transfer when peer start
     *
     */
    @Override
    public byte[][] appExecuteBatch(byte[][] commands, MessageContext[] msgCtxs, boolean fromConsensus) {

        // Not from consensus outcomes， from state transfer
        if (!fromConsensus) {
            return appExecuteDiffBatch(commands, msgCtxs);
        }

        return null;
    }

    /**
     *
     *  From consensus outcomes, do nothing now
     *  The operation of executing the batch was moved to the consensus stage 2 and 3, in order to guaranteed ledger consistency
     */
    @Override
    public byte[][] appExecuteBatch(byte[][] commands, MessageContext[] msgCtxs, boolean fromConsensus, List<ReplyContextMessage> replyList) {

//        if (replyList == null || replyList.size() == 0) {
//            throw new IllegalArgumentException();
//        }
//        // todo 此部分需要重新改造
//        /**
//         * 默认BFTSmart接口提供的commands是一个或多个共识结果的顺序集合
//         * 根据共识的规定，目前的做法是将其根据msgCtxs的内容进行分组，每组都作为一个结块标识来处理
//         * 从msgCtxs可以获取对应commands的分组情况
//         */
//        int manageConsensusId = msgCtxs[0].getConsensusId();
//        List<byte[]> manageConsensusCmds = new ArrayList<>();
//        List<ReplyContextMessage> manageReplyMsgs = new ArrayList<>();
//
//        int index = 0;
//        for (MessageContext msgCtx : msgCtxs) {
//            if (msgCtx.getConsensusId() == manageConsensusId) {
//                manageConsensusCmds.add(commands[index]);
//                manageReplyMsgs.add(replyList.get(index));
//            } else {
//                // 达到结块标准，需要进行结块并应答
//                blockAndReply(manageConsensusCmds, manageReplyMsgs);
//                // 重置链表和共识ID
//                manageConsensusCmds = new ArrayList<>();
//                manageReplyMsgs = new ArrayList<>();
//                manageConsensusId = msgCtx.getConsensusId();
//                manageConsensusCmds.add(commands[index]);
//                manageReplyMsgs.add(replyList.get(index));
//            }
//            index++;
//        }
//        // 结束时，肯定有最后一个结块请求未处理
//        if (!manageConsensusCmds.isEmpty()) {
//            blockAndReply(manageConsensusCmds, manageReplyMsgs);
//        }
        return null;
    }

    /**
     *
     *  Block and reply are moved to consensus completion stage
     *
     */
    private void blockAndReply(List<byte[]> manageConsensusCmds, List<ReplyContextMessage> replyList) {
//        consensusBatchId = messageHandle.beginBatch(realmName);
//        List<AsyncFuture<byte[]>> asyncFutureLinkedList = new ArrayList<>(manageConsensusCmds.size());
//        try {
//            int msgId = 0;
//            for (byte[] txContent : manageConsensusCmds) {
//                AsyncFuture<byte[]> asyncFuture = messageHandle.processOrdered(msgId++, txContent, realmName, consensusBatchId);
//                asyncFutureLinkedList.add(asyncFuture);
//            }
//            messageHandle.completeBatch(realmName, consensusBatchId);
//            messageHandle.commitBatch(realmName, consensusBatchId);
//        } catch (Exception e) {
//            // todo 需要处理应答码 404
//        	LOGGER.error("Error occurred while processing ordered messages! --" + e.getMessage(), e);
//            messageHandle.rollbackBatch(realmName, consensusBatchId, TransactionState.CONSENSUS_ERROR.CODE);
//        }
//
//        // 通知线程单独处理应答
//        notifyReplyExecutors.execute(() -> {
//            // 应答对应的结果
//            int replyIndex = 0;
//            for(ReplyContextMessage msg : replyList) {
//                msg.setReply(asyncFutureLinkedList.get(replyIndex).get());
//                TOMMessage request = msg.getTomMessage();
//                ReplyContext replyContext = msg.getReplyContext();
//                request.reply = new TOMMessage(replyContext.getId(), request.getSession(), request.getSequence(),
//                        request.getOperationId(), msg.getReply(), replyContext.getCurrentViewId(),
//                        request.getReqType());
//
//                if (replyContext.getNumRepliers() > 0) {
//                    bftsmart.tom.util.Logger.println("(ServiceReplica.receiveMessages) sending reply to "
//                            + request.getSender() + " with sequence number " + request.getSequence()
//                            + " and operation ID " + request.getOperationId() + " via ReplyManager");
//                    replyContext.getRepMan().send(request);
//                } else {
//                    bftsmart.tom.util.Logger.println("(ServiceReplica.receiveMessages) sending reply to "
//                            + request.getSender() + " with sequence number " + request.getSequence()
//                            + " and operation ID " + request.getOperationId());
//                    replyContext.getReplier().manageReply(request, msg.getMessageContext());
//                }
//                replyIndex++;
//            }
//        });
    }

    /**
     * Used by consensus write phase, pre compute new block hash
     * @param cid
     * 	      当前正在进行的共识ID；
     * @param commands
     *        请求列表
     */
    public BatchAppResultImpl preComputeAppHash(int cid, byte[][] commands) {

        List<AsyncFuture<byte[]>> asyncFutureLinkedList = new ArrayList<>(commands.length);
        List<byte[]> responseLinkedList = new ArrayList<>();
        StateSnapshot newStateSnapshot = null;
        StateSnapshot preStateSnapshot = null;
        StateSnapshot genisStateSnapshot = null;
        BatchAppResultImpl result = null;
        String batchId = null;
        int msgId = 0;
        try {
            batchHandleLock.lock();

//            long lastCid = stateHolder.lastCid, currentCid = stateHolder.currentCid;
//            if (cid < lastCid) {
//                // 表示该CID已经执行过，不再处理
//                return null;
//            } else if (cid == lastCid + 1) {
//                // 需要判断之前二阶段是否执行过
//                if (cid == currentCid) {
//                    // 表示二阶段已执行,回滚，重新执行
//                    String batchingID = stateHolder.batchingID;
//                    messageHandle.rollbackBatch(realmName, batchingID, TransactionState.IGNORED_BY_BLOCK_FULL_ROLLBACK.CODE);
//                }
//            }
//            stateHolder.currentCid = cid;

            if(commands.length == 0) {
                // 没有要做预计算的消息，直接组装结果返回
                result = new BatchAppResultImpl(responseLinkedList, int2Bytes(cid) , "", int2Bytes(cid));
                result.setErrorCode((byte) 0);
            } else {
                batchId = messageHandle.beginBatch(realmName);
                stateHolder.batchingID = batchId;

                // 创世区块的状态快照
                genisStateSnapshot = messageHandle.getGenisStateSnapshot(realmName);
                // 前置区块的状态快照
                preStateSnapshot = messageHandle.getStateSnapshot(realmName);
                if (preStateSnapshot == null) {
                    throw new IllegalStateException("Prev block state snapshot is null!");
                }
                for (int i = 0; i < commands.length; i++) {
                    byte[] txContent = commands[i];
                    AsyncFuture<byte[]> asyncFuture = messageHandle.processOrdered(msgId++, txContent, realmName, batchId);
                    asyncFutureLinkedList.add(asyncFuture);
                }

                newStateSnapshot = messageHandle.completeBatch(realmName, batchId);

                for (int i = 0; i < asyncFutureLinkedList.size(); i++) {
                    responseLinkedList.add(asyncFutureLinkedList.get(i).get());
                }

                result = new BatchAppResultImpl(responseLinkedList, newStateSnapshot.getSnapshot(), batchId, genisStateSnapshot.getSnapshot());
                result.setErrorCode((byte) 0);
            }
        } catch (BlockRollbackException e) {
            LOGGER.error("Error occurred while pre compute app! --" + e.getMessage(), e);
            for (int i = 0; i < commands.length; i++) {
                responseLinkedList.add(createAppResponse(commands[i],e.getState()));
            }

            result = new BatchAppResultImpl(responseLinkedList,preStateSnapshot.getSnapshot(), batchId, genisStateSnapshot.getSnapshot());
            result.setErrorCode((byte) 1);
        }catch (Exception e) {
            LOGGER.error("Error occurred while pre compute app! --" + e.getMessage(), e);
            for (int i = 0; i < commands.length; i++) {
                responseLinkedList.add(createAppResponse(commands[i],TransactionState.IGNORED_BY_BLOCK_FULL_ROLLBACK));
            }

            result = new BatchAppResultImpl(responseLinkedList,preStateSnapshot.getSnapshot(), batchId, genisStateSnapshot.getSnapshot());
            result.setErrorCode((byte) 1);
        }finally {
            batchHandleLock.unlock();
        }

        return result;
    }

    // Block full rollback responses, generated in pre compute phase, due to tx exception
    private byte[] createAppResponse(byte[] command, TransactionState transactionState) {
        TransactionRequest txRequest = BinaryProtocol.decode(command);

        TxResponseMessage resp = new TxResponseMessage(txRequest.getTransactionContent().getHash());

        resp.setExecutionState(transactionState);

        return BinaryProtocol.encode(resp, TransactionResponse.class);
    }

    public List<byte[]> updateAppResponses(List<byte[]> asyncResponseLinkedList, byte[] commonHash, boolean isConsistent) {
        List<byte[]> updatedResponses = new ArrayList<>();
        TxResponseMessage resp = null;

        for(int i = 0; i < asyncResponseLinkedList.size(); i++) {
            TransactionResponse txResponse = BinaryProtocol.decode(asyncResponseLinkedList.get(i));
            if (isConsistent) {
                resp = new TxResponseMessage(txResponse.getContentHash());
            }
            else {
                resp = new TxResponseMessage(new HashDigest(commonHash));
            }
            resp.setExecutionState(TransactionState.IGNORED_BY_BLOCK_FULL_ROLLBACK);
            updatedResponses.add(BinaryProtocol.encode(resp, TransactionResponse.class));
        }
        return updatedResponses;
    }
    /**
     *
     *  Decision has been made at the consensus stage， commit block
     *
     */
    public void preComputeAppCommit(int cid, String batchId) {
        try {
            batchHandleLock.lock();
//            long lastCid = stateHolder.lastCid;
//            if (cid <= lastCid) {
//                // 表示该CID已经执行过，不再处理
//                return;
//            }
//            stateHolder.setLastCid(cid);
            String batchingID = stateHolder.batchingID;
            stateHolder.reset();
            if (batchId.equals(batchingID) && !(batchingID.equals("".toString()))) {
                messageHandle.commitBatch(realmName, batchId);
            }
        } catch (BlockRollbackException e) {
            LOGGER.error("Error occurred while pre compute commit --" + e.getMessage(), e);
            throw e;
        } finally {
            batchHandleLock.unlock();
        }
    }

    /**
     *
     *  Consensus write phase will terminate, new block hash values are inconsistent, rollback block
     *
     */
    public void preComputeAppRollback(int cid, String batchId) {
        try {
            batchHandleLock.lock();
//            long lastCid = stateHolder.lastCid;
//            if (cid <= lastCid) {
//                // 表示该CID已经执行过，不再处理
//                return;
//            }
//            stateHolder.setLastCid(cid);
            String batchingID = stateHolder.batchingID;
            stateHolder.reset();
            LOGGER.debug("Rollback of operations that cause inconsistencies in the ledger");
            if (batchId.equals(batchingID) && !(batchingID.equals("".toString()))) {
                messageHandle.rollbackBatch(realmName, batchId, TransactionState.IGNORED_BY_BLOCK_FULL_ROLLBACK.CODE);
            }
        } catch (Exception e) {
            LOGGER.error("Error occurred while pre compute rollback --" + e.getMessage(), e);
            throw e;
        } finally {
            batchHandleLock.unlock();
        }
    }

    //notice
    public byte[] getSnapshot() {
        LOGGER.debug("------- GetSnapshot...[replica.id=" + this.getId() + "]");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BytesUtils.writeInt(stateHandles.size(), out);
        for (StateHandle stateHandle : stateHandles) {
            // TODO: 测试代码；
            return stateHandle.takeSnapshot();
        }
        return out.toByteArray();
    }

    public void installSnapshot(byte[] snapshot) {
//        System.out.println("Not implement!");
    }

    @Override
    public void start() {
        if (this.getId() < 0) {
            throw new IllegalStateException("Unset server node ID！");
        }
        LOGGER.info("=============================== Start replica ===================================");

        if (status != Status.STOPPED) {
            return;
        }
        synchronized (mutex) {
            if (status != Status.STOPPED) {
                return;
            }
            status = Status.STARTING;

            try {
                LOGGER.info("Start replica...[ID=" + getId() + "]");
//                this.replica = new ServiceReplica(tomConfig, this, this);
                this.replica = new ServiceReplica(tomConfig, this, this, (int)latestStateId -1, latestView);
                this.topology = new BftsmartTopology(replica.getReplicaContext().getCurrentView());
//                initOutTopology();
                status = Status.RUNNING;
//                createProxyClient();
                LOGGER.info(
                        "=============================== Replica started success! ===================================");
            } catch (RuntimeException e) {
                status = Status.STOPPED;
                throw e;
            }
        }

    }

    @Override
    public void stop() {
        if (status != Status.RUNNING) {
            return;
        }
        synchronized (mutex) {
            if (status != Status.RUNNING) {
                return;
            }
            status = Status.STOPPING;

            try {
                ServiceReplica rep = this.replica;
                if (rep != null) {
                    LOGGER.debug("Stop replica...[ID=" + rep.getId() + "]");
                    this.replica = null;
                    this.topology = null;

                    rep.kill();
                    LOGGER.debug("Replica had stopped! --[ID=" + rep.getId() + "]");
                }
            } finally {
                status = Status.STOPPED;
            }
        }
    }

    private void initOutTopology() {
        View currView = this.topology.getView();
        int id = currView.getId();
        int curProcessId = tomConfig.getProcessId();
        int f = currView.getF();
        int[] processes = currView.getProcesses();
        InetSocketAddress[] addresses = new InetSocketAddress[processes.length];
        for (int i = 0; i < processes.length; i++) {
            int pid = processes[i];
            if (curProcessId == pid) {
                addresses[i] = new InetSocketAddress(this.tomConfig.getHost(pid), this.tomConfig.getPort(pid));
            } else {
                addresses[i] = currView.getAddress(pid);
            }
        }
        View returnView = new View(id, processes, f, addresses);
        this.outerTopology = new BftsmartTopology(returnView);
    }

    enum Status {

        STARTING,

        RUNNING,

        STOPPING,

        STOPPED

    }

    private byte[] int2Bytes(int cid){
        byte[] arr = new byte[4] ;
        arr[0] = (byte)cid ;
        arr[1] = (byte)(cid >> 8) ;
        arr[2] = (byte)(cid >> 16) ;
        arr[3] = (byte)(cid >> 24) ;

        return arr;
    }

    private static class InnerStateHolder {

        private long lastCid;

        private long currentCid = -1L;

        private String batchingID = "";

        public InnerStateHolder(long lastCid) {
            this.lastCid = lastCid;
        }

        public InnerStateHolder(long lastCid, long currentCid) {
            this.lastCid = lastCid;
            this.currentCid = currentCid;
        }

        public long getLastCid() {
            return lastCid;
        }

        public void setLastCid(long lastCid) {
            this.lastCid = lastCid;
        }

        public long getCurrentCid() {
            return currentCid;
        }

        public void setCurrentCid(long currentCid) {
            this.currentCid = currentCid;
        }

        public String getBatchingID() {
            return batchingID;
        }

        public void setBatchingID(String batchingID) {
            this.batchingID = batchingID;
        }

        public void reset() {
            currentCid = -1;
            batchingID = "";
        }
    }

}
