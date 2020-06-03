package com.jd.blockchain.peer.web;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import bftsmart.reconfiguration.util.TOMConfiguration;
import bftsmart.reconfiguration.views.View;
import com.jd.blockchain.consensus.bftsmart.BftsmartClientIncomingSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartTopology;
import com.jd.blockchain.crypto.CryptoAlgorithm;
import com.jd.blockchain.crypto.CryptoProvider;
import com.jd.blockchain.ledger.core.TransactionSetQuery;
import com.jd.blockchain.ledger.json.CryptoConfigInfo;
import com.jd.blockchain.ledger.proof.MerkleData;
import com.jd.blockchain.ledger.proof.MerkleLeaf;
import com.jd.blockchain.ledger.proof.MerklePath;
import com.jd.blockchain.peer.consensus.LedgerStateManager;
import com.jd.blockchain.utils.ConsoleUtils;
import com.jd.blockchain.utils.net.NetworkAddress;
import com.jd.blockchain.utils.serialize.binary.BinarySerializeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.jd.blockchain.binaryproto.DataContractRegistry;
import com.jd.blockchain.consensus.ClientIdentification;
import com.jd.blockchain.consensus.ClientIdentifications;
import com.jd.blockchain.consensus.ClientIncomingSettings;
import com.jd.blockchain.consensus.ConsensusProvider;
import com.jd.blockchain.consensus.ConsensusProviders;
import com.jd.blockchain.consensus.ConsensusSettings;
import com.jd.blockchain.consensus.NodeSettings;
import com.jd.blockchain.consensus.action.ActionResponse;
import com.jd.blockchain.consensus.bftsmart.BftsmartConsensusSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartNodeSettings;
import com.jd.blockchain.consensus.mq.server.MsgQueueMessageDispatcher;
import com.jd.blockchain.consensus.service.MessageHandle;
import com.jd.blockchain.consensus.service.NodeServer;
import com.jd.blockchain.consensus.service.ServerSettings;
import com.jd.blockchain.consensus.service.StateMachineReplicate;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.ledger.ContractCodeDeployOperation;
import com.jd.blockchain.ledger.ContractEventSendOperation;
import com.jd.blockchain.ledger.CryptoSetting;
import com.jd.blockchain.ledger.DataAccountKVSetOperation;
import com.jd.blockchain.ledger.DataAccountRegisterOperation;
import com.jd.blockchain.ledger.EndpointRequest;
import com.jd.blockchain.ledger.LedgerAdminInfo;
import com.jd.blockchain.ledger.LedgerBlock;
import com.jd.blockchain.ledger.LedgerInitOperation;
import com.jd.blockchain.ledger.LedgerMetadata_V2;
import com.jd.blockchain.ledger.LedgerSettings;
import com.jd.blockchain.ledger.NodeRequest;
import com.jd.blockchain.ledger.Operation;
import com.jd.blockchain.ledger.ParticipantRegisterOperation;
import com.jd.blockchain.ledger.ParticipantStateUpdateOperation;
import com.jd.blockchain.ledger.PrivilegeSet;
import com.jd.blockchain.ledger.RoleInitSettings;
import com.jd.blockchain.ledger.RoleSet;
import com.jd.blockchain.ledger.RolesConfigureOperation;
import com.jd.blockchain.ledger.SecurityInitSettings;
import com.jd.blockchain.ledger.TransactionContent;
import com.jd.blockchain.ledger.TransactionContentBody;
import com.jd.blockchain.ledger.TransactionRequest;
import com.jd.blockchain.ledger.TransactionResponse;
import com.jd.blockchain.ledger.UserAuthInitSettings;
import com.jd.blockchain.ledger.UserAuthorizeOperation;
import com.jd.blockchain.ledger.UserRegisterOperation;
import com.jd.blockchain.ledger.core.LedgerManage;
import com.jd.blockchain.ledger.core.LedgerQuery;
import com.jd.blockchain.peer.ConsensusRealm;
import com.jd.blockchain.peer.LedgerBindingConfigAware;
import com.jd.blockchain.peer.PeerManage;
import com.jd.blockchain.setting.GatewayIncomingSetting;
import com.jd.blockchain.setting.LedgerIncomingSetting;
import com.jd.blockchain.storage.service.DbConnection;
import com.jd.blockchain.storage.service.DbConnectionFactory;
import com.jd.blockchain.tools.initializer.LedgerBindingConfig;
import com.jd.blockchain.tools.initializer.LedgerBindingConfig.BindingConfig;
import com.jd.blockchain.utils.Bytes;
import com.jd.blockchain.utils.io.ByteArray;
import com.jd.blockchain.web.converters.BinaryMessageConverter;

/**
 * 网关管理服务；
 * 
 * 提供
 * 
 * @author huanghaiquan
 *
 */
@RestController
@RequestMapping(path = "/management")
public class ManagementController implements LedgerBindingConfigAware, PeerManage {

	private static Logger LOGGER = LoggerFactory.getLogger(ManagementController.class);

	public static final String GATEWAY_PUB_EXT_NAME = ".gw.pub";

	public static final int MIN_GATEWAY_ID = 10000;

	@Autowired
	private LedgerManage ledgerManager;

	@Autowired
	private DbConnectionFactory connFactory;

	private Map<HashDigest, MsgQueueMessageDispatcher> ledgerTxConverters = new ConcurrentHashMap<>();

	private Map<HashDigest, NodeServer> ledgerPeers = new ConcurrentHashMap<>();
	private Map<HashDigest, CryptoSetting> ledgerCryptoSettings = new ConcurrentHashMap<>();


	private LedgerBindingConfig config;

	@Autowired
	private MessageHandle consensusMessageHandler;

	@Autowired
	private StateMachineReplicate consensusStateManager;

	static {
        DataContractRegistry.register(LedgerInitOperation.class);
		DataContractRegistry.register(LedgerBlock.class);
		DataContractRegistry.register(TransactionContent.class);
		DataContractRegistry.register(TransactionContentBody.class);
		DataContractRegistry.register(TransactionRequest.class);
		DataContractRegistry.register(NodeRequest.class);
		DataContractRegistry.register(EndpointRequest.class);
		DataContractRegistry.register(TransactionResponse.class);
		DataContractRegistry.register(DataAccountKVSetOperation.class);
		DataContractRegistry.register(DataAccountKVSetOperation.KVWriteEntry.class);

		DataContractRegistry.register(Operation.class);
		DataContractRegistry.register(ContractCodeDeployOperation.class);
		DataContractRegistry.register(ContractEventSendOperation.class);
		DataContractRegistry.register(DataAccountRegisterOperation.class);
		DataContractRegistry.register(UserRegisterOperation.class);
		DataContractRegistry.register(ParticipantRegisterOperation.class);
		DataContractRegistry.register(ParticipantStateUpdateOperation.class);

		DataContractRegistry.register(ActionResponse.class);

		DataContractRegistry.register(BftsmartConsensusSettings.class);
		DataContractRegistry.register(BftsmartNodeSettings.class);
		
		DataContractRegistry.register(LedgerAdminInfo.class);
		DataContractRegistry.register(LedgerSettings.class);

		// 注册角色/权限相关接口
		DataContractRegistry.register(RolesConfigureOperation.class);
		DataContractRegistry.register(RolesConfigureOperation.RolePrivilegeEntry.class);
		DataContractRegistry.register(UserAuthorizeOperation.class);
		DataContractRegistry.register(UserAuthorizeOperation.UserRolesEntry.class);
		DataContractRegistry.register(PrivilegeSet.class);
		DataContractRegistry.register(RoleSet.class);
		DataContractRegistry.register(SecurityInitSettings.class);
		DataContractRegistry.register(RoleInitSettings.class);
		DataContractRegistry.register(UserAuthInitSettings.class);
		DataContractRegistry.register(LedgerMetadata_V2.class);

		// 注册默克尔树相关接口
		DataContractRegistry.register(MerkleData.class);
		DataContractRegistry.register(MerkleLeaf.class);
		DataContractRegistry.register(MerklePath.class);

		// 注册加解密相关接口
		DataContractRegistry.register(CryptoSetting.class);
		DataContractRegistry.register(CryptoProvider.class);
		DataContractRegistry.register(CryptoAlgorithm.class);
		//TransactionSetQuery;
		DataContractRegistry.register(TransactionSetQuery.class);
	}

	/**
	 * 接入认证；
	 * 
	 * @param clientIdentifications
	 * @return
	 */
	@RequestMapping(path = "/gateway/auth", method = RequestMethod.POST, consumes = BinaryMessageConverter.CONTENT_TYPE_VALUE)
	public GatewayIncomingSetting authenticateGateway(@RequestBody ClientIdentifications clientIdentifications) {
		// 去掉不严谨的网关注册和认证逻辑；暂时先放开，不做认证，后续应该在链上注册网关信息，并基于链上的网关信息进行认证；
		// by: huanghaiquan; at 2018-09-11 18:34;
		// TODO: 实现网关的链上注册与认证机制；
		// TODO: 暂时先返回全部账本对应的共识网络配置信息；以账本哈希为 key 标识每一个账本对应的共识域、以及共识配置参数；
		if (ledgerPeers.size() == 0 || clientIdentifications == null) {
			return null;
		}

        ClientIdentification[] identificationArray = clientIdentifications.getClientIdentifications();
		if (identificationArray == null || identificationArray.length <= 0) {
		    return null;
        }

		GatewayIncomingSetting setting = new GatewayIncomingSetting();
		List<LedgerIncomingSetting> ledgerIncomingList = new ArrayList<LedgerIncomingSetting>();

		for (HashDigest ledgerHash : ledgerPeers.keySet()) {

			NodeServer peer = ledgerPeers.get(ledgerHash);

			String peerProviderName = peer.getProviderName();

			ConsensusProvider provider = ConsensusProviders.getProvider(peer.getProviderName());

            ClientIncomingSettings clientIncomingSettings = null;
            for (ClientIdentification authId : identificationArray) {
                if (authId.getProviderName() == null ||
                        authId.getProviderName().length() <= 0 ||
                        !authId.getProviderName().equalsIgnoreCase(peerProviderName)) {
                    continue;
                }
                try {
                    clientIncomingSettings = peer.getConsensusManageService().authClientIncoming(authId);

					//add for test the gateway connect to peer0; 20200514;
					if (clientIncomingSettings instanceof BftsmartClientIncomingSettings) {
						BftsmartClientIncomingSettings bftsmartClientIncomingSettings = (BftsmartClientIncomingSettings) clientIncomingSettings;
						byte[] topologyBytes = bftsmartClientIncomingSettings.getTopology();
						byte[] tomConfigBytes = bftsmartClientIncomingSettings.getTomConfig();
						BftsmartTopology topology = BinarySerializeUtils.deserialize(topologyBytes);
						TOMConfiguration tomConfig = BinarySerializeUtils.deserialize(tomConfigBytes);
						View view = topology.getView();
						if (view != null) {
							// 打印view
							int[] processes = view.getProcesses();
							for (int process : processes) {
								InetSocketAddress address = view.getAddress(process);
								if(LOGGER.isDebugEnabled()){
									LOGGER.debug("topology id = %s, address = %s \r\n",
											process, address);
									LOGGER.debug("tomConfig id = %s, host = %s, port = %s \r\n",
											process, tomConfig.getHost(process), tomConfig.getPort(process));
								}
							}
						}
					}

                    break;
                } catch (Exception e) {
                    throw new AuthenticationServiceException(e.getMessage(), e);
                }
            }
            if (clientIncomingSettings == null) {
                continue;
            }

			byte[] clientIncomingBytes = provider.getSettingsFactory().getIncomingSettingsEncoder()
					.encode(clientIncomingSettings);
			String base64ClientIncomingSettings = ByteArray.toBase64(clientIncomingBytes);

			LedgerIncomingSetting ledgerIncomingSetting = new LedgerIncomingSetting();
			ledgerIncomingSetting.setLedgerHash(ledgerHash);

			// 使用非代理对象，防止JSON序列化异常
			ledgerIncomingSetting.setCryptoSetting(new CryptoConfigInfo(ledgerCryptoSettings.get(ledgerHash)));
			ledgerIncomingSetting.setClientSetting(base64ClientIncomingSettings);
			ledgerIncomingSetting.setProviderName(peerProviderName);

			ledgerIncomingList.add(ledgerIncomingSetting);

		}
		setting.setLedgers(ledgerIncomingList.toArray(new LedgerIncomingSetting[ledgerIncomingList.size()]));
		return setting;
	}

	@Override
	public void setConfig(LedgerBindingConfig config) {
		// TODO 更新配置；暂时不考虑变化过程的平滑切换问题,后续完善该流程；
		// 1、检查账本的数据库配置；a、配置发生变化的账本，建立新的账本库(LedgerRepository)替换旧的实例；b、加入新增加的账本库实例；c、移除已经废弃的账本库；
		// 2、完成账本库更改后，读取最新的共识配置信息，更新共识域；
		// 3、基于当前共识地址检查共识域；a、启动新增加的共识地址，以及更新相应的共识域关系；c、已经废弃的共识域直接停止；
		try {
			// remove all existing ledger repositories;
			HashDigest[] existingLedgerHashs = ledgerManager.getLedgerHashs();
			for (HashDigest lh : existingLedgerHashs) {
				ledgerManager.unregister(lh);
			}
			HashDigest[] ledgerHashs = config.getLedgerHashs();
			for (HashDigest ledgerHash : ledgerHashs) {
				setConfig(config.getLedger(ledgerHash),ledgerHash);
			}

			this.config = config;

		} catch (Exception e) {
			LOGGER.error("Error occurred on configing LedgerBindingConfig! --" + e.getMessage(), e);
			throw new IllegalStateException(e);
		}
	}

	@Override
	public NodeServer setConfig(BindingConfig bindingConfig, HashDigest ledgerHash) {
//		LedgerBindingConfig.BindingConfig bindingConfig = config.getLedger(ledgerHash);
		DbConnection dbConnNew = connFactory.connect(bindingConfig.getDbConnection().getUri(),
				bindingConfig.getDbConnection().getPassword());
		LedgerQuery ledgerRepository = ledgerManager.register(ledgerHash, dbConnNew.getStorageService());

		// load provider;
		LedgerAdminInfo ledgerAdminAccount = ledgerRepository.getAdminInfo();
		String consensusProvider = ledgerAdminAccount.getSettings().getConsensusProvider();
		ConsensusProvider provider = ConsensusProviders.getProvider(consensusProvider);
		// find current node;
		Bytes csSettingBytes = ledgerAdminAccount.getSettings().getConsensusSetting();
		ConsensusSettings csSettings = provider.getSettingsFactory().getConsensusSettingsEncoder()
				.decode(csSettingBytes.toBytes());
		NodeSettings currentNode = null;
		for (NodeSettings nodeSettings : csSettings.getNodes()) {
			if (nodeSettings.getAddress().equals(bindingConfig.getParticipant().getAddress())) {
				currentNode = nodeSettings;
			}
		}
		if (currentNode == null) {
			throw new IllegalArgumentException(
					"Current node is not found from the consensus settings of ledger[" + ledgerHash.toBase58()
							+ "]!");
		}
		ServerSettings serverSettings = provider.getServerFactory().buildServerSettings(ledgerHash.toBase58(), csSettings, currentNode.getAddress());

		((LedgerStateManager)consensusStateManager).setLatestStateId(ledgerRepository.retrieveLatestBlockHeight());

		NodeServer server = provider.getServerFactory().setupServer(serverSettings, consensusMessageHandler,
				consensusStateManager);
		ledgerPeers.put(ledgerHash, server);
		ledgerCryptoSettings.put(ledgerHash, ledgerAdminAccount.getSettings().getCryptoSetting());

		return server;
	}

	@Override
	public ConsensusRealm[] getRealms() {
		throw new IllegalStateException("Not implemented!");
	}

	@Override
	public void runAllRealms() {
		for (NodeServer peer : ledgerPeers.values()) {
			runRealm(peer);
		}
	}

	@Override
	public void runRealm(NodeServer nodeServer) {
		nodeServer.start();
	}

	@Override
	public void closeAllRealms() {
		for (NodeServer peer : ledgerPeers.values()) {
			peer.stop();
		}
	}
}
