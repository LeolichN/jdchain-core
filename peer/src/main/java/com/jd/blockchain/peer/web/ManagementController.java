package com.jd.blockchain.peer.web;

import bftsmart.reconfiguration.Reconfiguration;
import bftsmart.reconfiguration.ReconfigureReply;
import bftsmart.reconfiguration.util.HostsConfig;
import bftsmart.reconfiguration.util.TOMConfiguration;
import bftsmart.reconfiguration.views.MemoryBasedViewStorage;
import bftsmart.reconfiguration.views.NodeNetwork;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.ServiceProxy;
import com.jd.blockchain.ca.CertificateRole;
import com.jd.blockchain.ca.CertificateUtils;
import com.jd.blockchain.consensus.NodeNetworkAddress;
import com.jd.blockchain.consensus.bftsmart.service.BftsmartNodeState;
import com.jd.blockchain.crypto.AddressEncoding;
import com.jd.blockchain.ledger.BlockRollbackException;
import com.jd.blockchain.ledger.IdentityMode;
import com.jd.blockchain.ledger.AccountState;
import com.jd.blockchain.ledger.core.UserAccount;
import com.jd.blockchain.sdk.proxy.HttpBlockchainBrowserService;
import com.jd.blockchain.transaction.BlockchainQueryService;
import com.jd.httpservice.agent.HttpServiceAgent;
import com.jd.httpservice.agent.ServiceConnection;
import com.jd.httpservice.agent.ServiceConnectionManager;
import com.jd.httpservice.agent.ServiceEndpoint;
import utils.BusinessException;
import utils.Bytes;
import utils.PropertiesUtils;
import utils.Property;
import utils.StringUtils;
import utils.codec.Base58Utils;
import utils.io.ByteArray;
import utils.io.BytesUtils;
import utils.io.Storage;
import utils.net.NetworkAddress;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.jd.binaryproto.BinaryProtocol;
import com.jd.binaryproto.DataContractRegistry;
import com.jd.blockchain.consensus.ClientCredential;
import com.jd.blockchain.consensus.ClientIncomingSettings;
import com.jd.blockchain.consensus.ConsensusProvider;
import com.jd.blockchain.consensus.ConsensusProviders;
import com.jd.blockchain.consensus.ConsensusViewSettings;
import com.jd.blockchain.consensus.NodeSettings;
import com.jd.blockchain.consensus.action.ActionResponse;
import com.jd.blockchain.consensus.bftsmart.BftsmartConsensusViewSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartNodeSettings;
import com.jd.blockchain.consensus.service.MessageHandle;
import com.jd.blockchain.consensus.service.NodeServer;
import com.jd.blockchain.consensus.service.NodeState;
import com.jd.blockchain.consensus.service.ServerSettings;
import com.jd.blockchain.consensus.service.StateMachineReplicate;
import com.jd.blockchain.crypto.AsymmetricKeypair;
import com.jd.blockchain.crypto.Crypto;
import com.jd.blockchain.crypto.CryptoAlgorithm;
import com.jd.blockchain.crypto.CryptoProvider;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.crypto.KeyGenUtils;
import com.jd.blockchain.crypto.PrivKey;
import com.jd.blockchain.crypto.PubKey;
import com.jd.blockchain.ledger.BlockchainIdentityData;
import com.jd.blockchain.ledger.ConsensusSettingsUpdateOperation;
import com.jd.blockchain.ledger.ContractCodeDeployOperation;
import com.jd.blockchain.ledger.ContractEventSendOperation;
import com.jd.blockchain.ledger.CreateProxyClientException;
import com.jd.blockchain.ledger.CryptoSetting;
import com.jd.blockchain.ledger.DataAccountKVSetOperation;
import com.jd.blockchain.ledger.DataAccountRegisterOperation;
import com.jd.blockchain.ledger.DigitalSignature;
import com.jd.blockchain.ledger.EventAccountRegisterOperation;
import com.jd.blockchain.ledger.EventPublishOperation;
import com.jd.blockchain.ledger.LedgerAdminInfo;
import com.jd.blockchain.ledger.LedgerBlock;
import com.jd.blockchain.ledger.LedgerInitOperation;
import com.jd.blockchain.ledger.LedgerMetadata_V2;
import com.jd.blockchain.ledger.LedgerSettings;
import com.jd.blockchain.ledger.LedgerTransaction;
import com.jd.blockchain.ledger.LedgerTransactions;
import com.jd.blockchain.ledger.Operation;
import com.jd.blockchain.ledger.ParticipantNode;
import com.jd.blockchain.ledger.ParticipantNodeState;
import com.jd.blockchain.ledger.ParticipantRegisterOperation;
import com.jd.blockchain.ledger.ParticipantStateUpdateOperation;
import com.jd.blockchain.ledger.PrivilegeSet;
import com.jd.blockchain.ledger.RoleInitSettings;
import com.jd.blockchain.ledger.RoleSet;
import com.jd.blockchain.ledger.RolesConfigureOperation;
import com.jd.blockchain.ledger.SecurityInitSettings;
import com.jd.blockchain.ledger.StartServerException;
import com.jd.blockchain.ledger.TransactionContent;
import com.jd.blockchain.ledger.TransactionRequest;
import com.jd.blockchain.ledger.TransactionRequestBuilder;
import com.jd.blockchain.ledger.TransactionResponse;
import com.jd.blockchain.ledger.TransactionState;
import com.jd.blockchain.ledger.UserAuthInitSettings;
import com.jd.blockchain.ledger.UserAuthorizeOperation;
import com.jd.blockchain.ledger.UserRegisterOperation;
import com.jd.blockchain.ledger.ViewUpdateException;
import com.jd.blockchain.ledger.core.DefaultOperationHandleRegisteration;
import com.jd.blockchain.ledger.core.LedgerEditor;
import com.jd.blockchain.ledger.core.LedgerManage;
import com.jd.blockchain.ledger.core.LedgerQuery;
import com.jd.blockchain.ledger.core.LedgerRepository;
import com.jd.blockchain.ledger.core.OperationHandleRegisteration;
import com.jd.blockchain.ledger.core.TransactionBatchProcessor;
import com.jd.blockchain.ledger.json.CryptoConfigInfo;
import com.jd.blockchain.ledger.merkletree.HashBucketEntry;
import com.jd.blockchain.ledger.merkletree.KeyIndex;
import com.jd.blockchain.ledger.merkletree.MerkleIndex;
import com.jd.blockchain.ledger.proof.MerkleKey;
import com.jd.blockchain.ledger.proof.MerkleLeaf;
import com.jd.blockchain.ledger.proof.MerklePath;
import com.jd.blockchain.ledger.proof.MerkleTrieData;
import com.jd.blockchain.peer.ConsensusRealm;
import com.jd.blockchain.peer.LedgerBindingConfigAware;
import com.jd.blockchain.peer.PeerManage;
import com.jd.blockchain.peer.consensus.LedgerStateManager;
import com.jd.blockchain.sdk.AccessSpecification;
import com.jd.blockchain.sdk.GatewayAuthRequest;
import com.jd.blockchain.sdk.ManagementHttpService;
import com.jd.blockchain.service.TransactionBatchResultHandle;
import com.jd.blockchain.setting.GatewayAuthResponse;
import com.jd.blockchain.setting.LedgerIncomingSettings;
import com.jd.blockchain.storage.service.DbConnection;
import com.jd.blockchain.storage.service.DbConnectionFactory;
import com.jd.blockchain.tools.initializer.LedgerBindingConfig;
import com.jd.blockchain.tools.initializer.LedgerBindingConfig.BindingConfig;
import com.jd.blockchain.transaction.SignatureUtils;
import com.jd.blockchain.transaction.TxBuilder;
import com.jd.blockchain.transaction.TxRequestMessage;
import com.jd.blockchain.transaction.TxResponseMessage;
import com.jd.blockchain.web.converters.BinaryMessageConverter;
import com.jd.httpservice.utils.web.WebResponse;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PreDestroy;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static com.jd.blockchain.consensus.bftsmart.BftsmartConsensusSettingsBuilder.*;
import static com.jd.blockchain.ledger.TransactionState.LEDGER_ERROR;

/**
 * 网关管理服务；
 *
 * 提供
 *
 * @author huanghaiquan
 *
 */
@RestController
@RequestMapping(path = ManagementHttpService.URL_MANAGEMENT)
public class ManagementController implements LedgerBindingConfigAware, PeerManage, ManagementHttpService {

	private static final String STORAGE_CONSENSUS = "consensus";

	private static Logger LOGGER = LoggerFactory.getLogger(ManagementController.class);

	public static final String BFTSMART_PROVIDER = "com.jd.blockchain.consensus.bftsmart.BftsmartConsensusProvider";

	public String DEFAULT_DIR = "";

	public String logDefaultFile;

	@Autowired
	private Storage storage;

	@Autowired
	private LedgerManage ledgerManager;

	@Autowired
	private DbConnectionFactory connFactory;

	private Map<HashDigest, NodeServer> ledgerPeers = new ConcurrentHashMap<>();

	private Map<HashDigest, CryptoSetting> ledgerCryptoSettings = new ConcurrentHashMap<>();

	private Map<HashDigest, AsymmetricKeypair> ledgerKeypairs = new ConcurrentHashMap<>();

	private Map<HashDigest, ParticipantNode> ledgerCurrNodes = new ConcurrentHashMap<>();

	private Map<HashDigest, LedgerQuery> ledgerQuerys = new ConcurrentHashMap<>();

	private Map<HashDigest, IdentityMode> ledgerIdMode = new ConcurrentHashMap<>();

	@Autowired
	private MessageHandle consensusMessageHandler;

	@Autowired
	private StateMachineReplicate consensusStateManager;

	static {
		DataContractRegistry.register(LedgerInitOperation.class);
		DataContractRegistry.register(LedgerBlock.class);
		DataContractRegistry.register(TransactionContent.class);
		DataContractRegistry.register(TransactionRequest.class);
		DataContractRegistry.register(TransactionResponse.class);
		DataContractRegistry.register(DataAccountKVSetOperation.class);
		DataContractRegistry.register(DataAccountKVSetOperation.KVWriteEntry.class);
		DataContractRegistry.register(EventPublishOperation.class);
		DataContractRegistry.register(EventPublishOperation.EventEntry.class);

		DataContractRegistry.register(Operation.class);
		DataContractRegistry.register(ContractCodeDeployOperation.class);
		DataContractRegistry.register(ContractEventSendOperation.class);
		DataContractRegistry.register(DataAccountRegisterOperation.class);
		DataContractRegistry.register(EventAccountRegisterOperation.class);
		DataContractRegistry.register(UserRegisterOperation.class);
		DataContractRegistry.register(ParticipantRegisterOperation.class);
		DataContractRegistry.register(ParticipantStateUpdateOperation.class);
		DataContractRegistry.register(ConsensusSettingsUpdateOperation.class);

		DataContractRegistry.register(ActionResponse.class);

		DataContractRegistry.register(BftsmartConsensusViewSettings.class);
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
		DataContractRegistry.register(MerkleTrieData.class);
		DataContractRegistry.register(MerkleKey.class);
		DataContractRegistry.register(MerkleLeaf.class);
		DataContractRegistry.register(MerklePath.class);
		DataContractRegistry.register(MerkleIndex.class);
		DataContractRegistry.register(KeyIndex.class);
		DataContractRegistry.register(HashBucketEntry.class);

		// 注册加解密相关接口
		DataContractRegistry.register(CryptoSetting.class);
		DataContractRegistry.register(CryptoProvider.class);
		DataContractRegistry.register(CryptoAlgorithm.class);
	}

	@RequestMapping(path = URL_GET_ACCESS_SPEC, method = RequestMethod.GET)
	@Override
	public AccessSpecification getAccessSpecification() {
		HashDigest[] ledgers = new HashDigest[ledgerPeers.size()];
		String[] consensusProviders = new String[ledgers.length];
		int i = 0;
		for (Entry<HashDigest, NodeServer> ledgerNode : ledgerPeers.entrySet()) {
			ledgers[i] = ledgerNode.getKey();
			consensusProviders[i] = ledgerNode.getValue().getProviderName();
			i++;
		}
		return new AccessSpecification(ledgers, consensusProviders);
	}

	/**
	 * 接入认证；
	 *
	 * @param authRequest
	 * @return
	 */
	@RequestMapping(path = URL_AUTH_GATEWAY, method = RequestMethod.POST, consumes = BinaryMessageConverter.CONTENT_TYPE_VALUE)
	@Override
	public GatewayAuthResponse authenticateGateway(@RequestBody GatewayAuthRequest authRequest) {
		if (ledgerPeers.size() == 0 || authRequest == null) {
			return null;
		}

		HashDigest[] authLedgers = authRequest.getLedgers();
		ClientCredential[] clientCredentialOfRequests = authRequest.getCredentials();
		if (authLedgers == null || authLedgers.length == 0 || clientCredentialOfRequests == null
				|| clientCredentialOfRequests.length == 0) {
			return null;
		}

		GatewayAuthResponse gatewayAuthResponse = new GatewayAuthResponse();
		List<LedgerIncomingSettings> ledgerIncomingList = new ArrayList<LedgerIncomingSettings>();

		int i = -1;
		for (HashDigest ledgerHash : authLedgers) {
			i++;
			NodeServer peer = ledgerPeers.get(ledgerHash);
			if (peer == null) {
				continue;
			}

			String peerProviderName = peer.getProviderName();

			ConsensusProvider provider = ConsensusProviders.getProvider(peer.getProviderName());

			ClientIncomingSettings clientIncomingSettings = null;
			ClientCredential clientRedential = clientCredentialOfRequests[i];
			if (!peerProviderName.equalsIgnoreCase(clientRedential.getProviderName())) {
				// 忽略掉不匹配的“共识客户端提供者程序”认证信息；
				continue;
			}

			// 用户账户校验，必须为非移除状态的共识节点
			LedgerRepository ledgerRepo = (LedgerRepository) ledgerQuerys.get(ledgerHash);
			if(null == ledgerRepo) {
				continue;
			}
			boolean isParticipantNode = false;
			PubKey clientPubKey = clientRedential.getPubKey();
			for(ParticipantNode participantNode : ledgerRepo.getAdminInfo().getParticipants()) {
				if(participantNode.getPubKey().equals(clientPubKey) &&
						participantNode.getParticipantNodeState() != ParticipantNodeState.DEACTIVATED) {
					isParticipantNode = true;
					break;
				}
			}
			if(!isParticipantNode) {
				continue;
			}

			try {
				// 证书模式下认证校验
				if(ledgerIdMode.get(ledgerHash) == IdentityMode.CA) {
					// 当前Peer证书
					UserAccount peerAccount = ledgerRepo.getUserAccountSet().getAccount(ledgerCurrNodes.get(ledgerHash).getAddress());
					if(peerAccount.getState() != AccountState.NORMAL) {
						LOGGER.error(String.format("Authenticate ledger[%s] error ! peer state is [%s]", ledgerHash.toBase58(), peerAccount.getState()));
						continue;
					}
					X509Certificate peerCA = CertificateUtils.parseCertificate(peerAccount.getCertificate());
					CertificateUtils.checkCertificateRole(peerCA, CertificateRole.PEER);
					CertificateUtils.checkValidity(peerCA);

					X509Certificate[] ledgerCAs = CertificateUtils.parseCertificates(ledgerRepo.getAdminInfo().getMetadata().getLedgerCertificates());
					Arrays.stream(ledgerCAs).forEach(issuer -> CertificateUtils.checkCACertificate(issuer));

					// 当前账本证书中当前节点证书发布者
					X509Certificate[] peerIssuers = CertificateUtils.findIssuers(peerCA, ledgerCAs);
					CertificateUtils.checkValidityAny(peerIssuers);

					// 接入网关CA
					UserAccount gwAccount = ledgerRepo.getUserAccountSet().getAccount(AddressEncoding.generateAddress(clientPubKey));
					if(gwAccount.getState() != AccountState.NORMAL) {
						LOGGER.error(String.format("Authenticate ledger[%s] error ! gateway state is [%s]", ledgerHash.toBase58(), peerAccount.getState()));
						continue;
					}
					X509Certificate gwCA = CertificateUtils.parseCertificate(gwAccount.getCertificate());
					CertificateUtils.checkCertificateRole(gwCA, CertificateRole.GW);
					CertificateUtils.checkValidity(gwCA);
					X509Certificate[] gwIssuers = CertificateUtils.findIssuers(gwCA, ledgerCAs);
					CertificateUtils.checkValidityAny(gwIssuers);
				}
				clientIncomingSettings = peer.getClientAuthencationService().authencateIncoming(clientRedential);
			} catch (Exception e) {
				// 个别账本的认证失败不应该影响其它账本的认证；
				LOGGER.error(String.format("Authenticate ledger[%s] error !", ledgerHash.toBase58()), e);
				continue;
			}

			byte[] clientIncomingBytes = provider.getSettingsFactory().getIncomingSettingsEncoder()
					.encode(clientIncomingSettings);
			String base64ClientIncomingSettings = ByteArray.toBase64(clientIncomingBytes);

			LedgerIncomingSettings ledgerIncomingSetting = new LedgerIncomingSettings();
			ledgerIncomingSetting.setLedgerHash(ledgerHash);

			// 使用非代理对象，防止JSON序列化异常
			ledgerIncomingSetting.setCryptoSetting(new CryptoConfigInfo(ledgerCryptoSettings.get(ledgerHash)));
			ledgerIncomingSetting.setConsensusClientSettings(base64ClientIncomingSettings);
			ledgerIncomingSetting.setProviderName(peerProviderName);

			ledgerIncomingList.add(ledgerIncomingSetting);

		}
		gatewayAuthResponse
				.setLedgers(ledgerIncomingList.toArray(new LedgerIncomingSettings[ledgerIncomingList.size()]));
		return gatewayAuthResponse;
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
				// 不同的账本实现处理隔离
				try {
					setConfig(config.getLedger(ledgerHash), ledgerHash);
				} catch (Exception e) {
					LOGGER.error("Exception occurred on setConfig! Exception ledger = {}, Exception cause = {}", Base58Utils.encode(ledgerHash.toBytes()), e.getMessage());
					continue;
				}
			}

		} catch (Exception e) {
			LOGGER.error("Peer start exception, Error occurred on configing LedgerBindingConfig! --" + e.getMessage(), e);
			throw new IllegalStateException(e);
		}
	}

	@Override
	public NodeServer setConfig(BindingConfig bindingConfig, HashDigest ledgerHash) {
//		LedgerBindingConfig.BindingConfig bindingConfig = config.getLedger(ledgerHash);
		LedgerQuery ledgerRepository = null;
		NodeServer server = null;
		ParticipantNode currentNode = null;
		LedgerAdminInfo ledgerAdminAccount = null;

		try {
			DbConnection dbConnNew = connFactory.connect(bindingConfig.getDbConnection().getUri(),
					bindingConfig.getDbConnection().getPassword());
			ledgerRepository = ledgerManager.register(ledgerHash, dbConnNew.getStorageService(), bindingConfig.getDbConnection().getAnchor());

			ledgerAdminAccount = ledgerRepository.getAdminInfo();

			ConsensusProvider provider = getProvider(ledgerAdminAccount);

			// load consensus setting;
			ConsensusViewSettings csSettings = getConsensusSetting(ledgerAdminAccount);

			// find current node;

			for (ParticipantNode participantNode : ledgerAdminAccount.getParticipants()) {
				if (participantNode.getAddress().toString().equals(bindingConfig.getParticipant().getAddress())) {
					currentNode = participantNode;
					break;
				}
			}
			if (currentNode == null) {
				throw new IllegalArgumentException("Current node is not found from the participant settings of ledger["
						+ ledgerHash.toBase58() + "]!");
			}

			LedgerMetadata_V2 metadata = ledgerRepository.getAdminInfo().getMetadata();
			ledgerIdMode.put(ledgerHash, null != metadata.getIdentityMode() ? metadata.getIdentityMode() : IdentityMode.KEYPAIR);
			if(metadata.getIdentityMode() == IdentityMode.CA) {
				X509Certificate peerCA = CertificateUtils.parseCertificate(ledgerRepository.getUserAccountSet().getAccount(currentNode.getAddress()).getCertificate());
				X509Certificate[] issuers = CertificateUtils.findIssuers(peerCA, CertificateUtils.parseCertificates(metadata.getLedgerCertificates()));
				// 校验根证书
				Arrays.stream(issuers).forEach(issuer -> CertificateUtils.checkCACertificate(issuer));
				CertificateUtils.checkValidityAny(issuers);
				// 校验节点证书
				CertificateUtils.checkCertificateRole(peerCA, CertificateRole.PEER);
				CertificateUtils.checkValidity(peerCA);
			}
			// 处于ACTIVED状态的参与方才会创建共识节点服务
			if (currentNode.getParticipantNodeState() == ParticipantNodeState.CONSENSUS) {
				ServerSettings serverSettings = provider.getServerFactory().buildServerSettings(ledgerHash.toBase58(), csSettings, currentNode.getAddress().toBase58());
				((LedgerStateManager) consensusStateManager).setLatestStateId(ledgerRepository.retrieveLatestBlockHeight());
				Storage consensusRuntimeStorage = getConsensusRuntimeStorage(ledgerHash);
				server = provider.getServerFactory().setupServer(serverSettings, consensusMessageHandler,
						consensusStateManager, consensusRuntimeStorage);
				ledgerPeers.put(ledgerHash, server);
			}
			ledgerQuerys.put(ledgerHash, ledgerRepository);
			ledgerCurrNodes.put(ledgerHash, currentNode);
			ledgerCryptoSettings.put(ledgerHash, ledgerAdminAccount.getSettings().getCryptoSetting());
			ledgerKeypairs.put(ledgerHash, loadIdentity(currentNode, bindingConfig));
		} catch (Exception e) {
			ledgerManager.unregister(ledgerHash);
			throw e;
		}

		return server;
	}

	/**
	 * 返回指定账本的共识运行时存储；
	 *
	 * @param ledgerHash
	 * @return
	 */
	private Storage getConsensusRuntimeStorage(HashDigest ledgerHash) {
		return storage.getStorage(ledgerHash.toBase58()).getStorage(STORAGE_CONSENSUS);
	}

	@Override
	public ConsensusRealm[] getRealms() {
		throw new IllegalStateException("Not implemented!");
	}

	@Override
	public void runAllRealms() {
		if (ledgerPeers != null && !ledgerPeers.isEmpty()) {
			// 每个账本使用独立的线程启动
			ThreadPoolExecutor executor = initLedgerLoadExecutor(ledgerPeers.size());
			for (NodeServer peer : ledgerPeers.values()) {
				executor.execute(() -> {
					runRealm(peer);
				});
			}
		}
	}

	@Override
	public void runRealm(NodeServer nodeServer) {
		nodeServer.start();
	}

	@PreDestroy
	public void destroy() {
		LOGGER.info("Destroy ManagementController Bean!");
		closeAllRealms();
	}

	@Override
	public void closeAllRealms() {
		for (NodeServer peer : ledgerPeers.values()) {
			peer.stop();
		}
	}

	@RequestMapping(path = "/monitor/consensus/nodestate/{ledgerHash}", method = RequestMethod.GET)
	public NodeState getConsensusNodeState(@PathVariable("ledgerHash") String base58LedgerHash) {
		byte[] ledgerHashBytes;
		try {
			ledgerHashBytes = Base58Utils.decode(base58LedgerHash);
		} catch (Exception e) {
			String errMsg = "Error occurred while resolving the base58 ledger hash string[" + base58LedgerHash + "]! --"
					+ e.getMessage();
			LOGGER.error(errMsg, e);
			throw new BusinessException(errMsg);
		}
		HashDigest ledgerHash;
		try {
			ledgerHash = Crypto.resolveAsHashDigest(ledgerHashBytes);
		} catch (Exception e) {
			String errMsg = "Error occurred while resolving the ledger hash[" + base58LedgerHash + "]! --"
					+ e.getMessage();
			LOGGER.error(errMsg, e);
			throw new BusinessException(errMsg);
		}
		NodeServer nodeServer = ledgerPeers.get(ledgerHash);
		if (nodeServer == null) {
			throw new BusinessException("The consensus node of ledger[" + base58LedgerHash + "] don't exist!");
		}
		try {
//			String stateInfo = JSONSerializeUtils.serializeToJSON(nodeServer.getState(), true);
			return nodeServer.getState();
		} catch (Exception e) {
			String errMsg = "Error occurred while detecting the state info of the current consensus node in ledger["
					+ base58LedgerHash + "]! --" + e.getMessage();
			LOGGER.error(errMsg, e);
			throw new BusinessException(errMsg);
		}
	}

	/**
	 * 输出当前节点状态到日志文件
	 * @return
	 */
	@RequestMapping(path = "/node/log", method = RequestMethod.GET)
	public void createNodeLog() {
		if (DEFAULT_DIR.length() == 0) {
			try {
				URL resource = ManagementController.class.getResource("/");
				if (resource != null) {
					String libPath = resource.getPath();
					if (libPath != null && libPath.length() > 0) {
						DEFAULT_DIR = libPath;
						this.logDefaultFile = File.separator + new SimpleDateFormat("yyyy-MM-dd :hh:mm:ss").format(Calendar.getInstance().getTime()) + "-node.log";
					}
				} else {
					File libDir = new File(ManagementController.class.getProtectionDomain().getCodeSource().getLocation().getPath());
					LOGGER.info("ManagementController's lib path = {} !", libDir.getAbsolutePath());
					DEFAULT_DIR = libDir.getParentFile().getParentFile().getPath();
					this.logDefaultFile = File.separator + "logs" + File.separator + new SimpleDateFormat("yyyy-MM-dd :hh:mm:ss").format(Calendar.getInstance().getTime()) + "-node.log";
					LOGGER.debug("logDefaultFile = {}", logDefaultFile);
				}
			} catch (Exception e) {
				LOGGER.error("create node log file error!", e);
			}
		}

		try {
			String logPath = DEFAULT_DIR + logDefaultFile;
			File nodeLogFile = new File(logPath);

			if(!nodeLogFile.exists()) {
				nodeLogFile.createNewFile();
			}

			BufferedWriter out = new BufferedWriter(new FileWriter(nodeLogFile,true));
			writeStateToLog(out);

			out.flush();
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void writeStateToLog(BufferedWriter out) {
		try {
			for (HashDigest ledgerHash : ledgerPeers.keySet()) {

				String base58LedgerHash = Base58Utils.encode(ledgerHash.toBytes());
				NodeServer nodeServer = ledgerPeers.get(ledgerHash);

				if (nodeServer == null) {
					throw new BusinessException("The consensus node of ledger[" + base58LedgerHash + "] don't exist!");
				}

				BftsmartNodeState nodeState = (BftsmartNodeState) nodeServer.getState();

				out.write("==========================Ledger = " + base58LedgerHash + "=============================\r\n");

				out.write("Time = " + new SimpleDateFormat("yyyy-MM-dd :hh:mm:ss:SSS").format(Calendar.getInstance().getTime()) + "\r\n");

				out.write("###Node State:### \r\n");
				out.write("{Running : " + String.valueOf(nodeState.isRunning()) + ", ");
				out.write("NodeID : " + String.valueOf(nodeState.getNodeID()) + ", ");
				out.write("isLeader : " + String.valueOf(nodeState.isLeader()) + "}\r\n");

				out.write("###View State:### \r\n");
				out.write("{ViewID: " + String.valueOf(nodeState.getViewState().getViewID()) + ", " + "ViewN : " + String.valueOf(nodeState.getViewState().getViewN()) + ", " +
						"ViewF: " + String.valueOf(nodeState.getViewState().getViewF()) +  ", " + "Quorum: " + String.valueOf(nodeState.getViewState().getQuorum()) + "}\r\n");

				out.write("View Procs: {");
				int procCount = 0, procs = nodeState.getViewState().getProcessIDs().length;
				for (int procid : nodeState.getViewState().getProcessIDs()) {
					out.write(String.valueOf(procid));
					if (++procCount != procs) {
						out.write(",");
					} else {
						out.write("}\r\n");
					}
				}
				out.write("View Procs Address: {");
				int addressCount = 0;
				for (NodeNetworkAddress nodeNetworkAddress : nodeState.getViewState().getProcessNetAddresses()) {
					out.write("(host: " + nodeNetworkAddress.getHost() + ", consensusport: " + String.valueOf(nodeNetworkAddress.getConsensusPort()) + ", monitorport: " + String.valueOf(nodeNetworkAddress.getMonitorPort()) + ")");
					if (++addressCount != procs) {
						out.write(",");
					} else {
						out.write("}\r\n");
					}
				}

				out.write("###Consensus State:###\r\n");
				out.write("{currentcid: " + String.valueOf(nodeState.getConsensusState().getConensusID()) + ", lastcid: " + String.valueOf(nodeState.getConsensusState().getLastConensusID()) + ", leaderid: " + String.valueOf(nodeState.getConsensusState().getLeaderID()) + "}\r\n");

				out.write("###Leader State:###\r\n");
				out.write("{leaderid: " + String.valueOf(nodeState.getLeaderState().getLeaderID()) + ", lastregency: " + String.valueOf(nodeState.getLeaderState().getLastRegency()) + ", nxtregency: " + String.valueOf(nodeState.getLeaderState().getNextRegency()) + "}\r\n");

				out.write("###Communication State:###\r\n");
				out.write("{tomlayerRunning: " + String.valueOf(nodeState.getCommunicationState().isTomLayerRunning()) +", tomThreadAlived: " + String.valueOf(nodeState.getCommunicationState().isTomLayerThreadAlived()) + ", deliverThreadAlived: " + String.valueOf(nodeState.getCommunicationState().isDeliverThreadAlived()) + "}\r\n");
				out.write("\r\n");
			}
		} catch (Exception e) {
			LOGGER.error("write state to node log file error!", e);
		}
	}

	/**
     * 区块同步：
     *    从指定节点同步最新区块信息，调用此接口会执行NodeServer重建
     *
     * @param ledgerHash    账本
     * @param syncHost  同步节点IP
     * @param syncPort  同步节点端口
     * @return
     */
	@RequestMapping(path = "/block/sync", method = RequestMethod.POST)
	public WebResponse syncBlock(@RequestParam("ledgerHash") String ledgerHash,
								   @RequestParam("syncHost") String syncHost,
								   @RequestParam("syncPort") int syncPort) {
		try {
			HashDigest ledger = Crypto.resolveAsHashDigest(Base58Utils.decode(ledgerHash));
			if (!ledgerKeypairs.containsKey(ledger)) {
				return WebResponse.createFailureResult(-1, "[ManagementController] input ledger hash not exist!");
			}

			LedgerRepository ledgerRepo = (LedgerRepository) ledgerQuerys.get(ledger);

			LedgerBlock ledgerLatestBlock = ledgerRepo.retrieveLatestBlock();
			LedgerAdminInfo ledgerAdminInfo = ledgerRepo.getAdminInfo(ledgerLatestBlock);

			// 目前仅支持BFT-SMaRt
			if (ledgerAdminInfo.getSettings().getConsensusProvider().equals(BFTSMART_PROVIDER)) {

				// 检查本地节点与远端节点在库上是否存在差异,有差异的进行差异交易重放
				WebResponse webResponse = checkLedgerDiff(ledgerRepo, ledgerLatestBlock, ledgerKeypairs.get(ledger), syncHost, syncPort);
				if (!webResponse.isSuccess()) {
					return webResponse;
				}

				// 重建 NodeServer
				setupServer(ledgerRepo, false);

				LOGGER.info("[ManagementController] sync block success!");

                return WebResponse.createSuccessResult(null);

			} else {
				return WebResponse.createSuccessResult(null);
			}

		} catch (Exception e) {
			LOGGER.error("[ManagementController] sync block failed!", e);
			return WebResponse.createFailureResult(-1, "[ManagementController] sync block failed! " + e.getMessage());
		}
	}

	/**
	 * 代理交易； <br>
	 *
	 * 此方法假设当前节点是一个新建但尚未加入共识网络的共识节点, 通过此方法接收一笔用于实现管理操作的交易；
	 *
	 * <p>
	 *
	 * 此方法接收到交易之后，先把交易提交到已有的共识网络执行； <br>
	 *
	 * 如果交易通过验证并执行成功，则将交易在本地的账本中以本地方式执行; <br>
	 *
	 * 如果执行之后的新区块一致，则提交本地区块；
	 *
	 * <p>
	 * 如果操作中涉及到共识参与方的共识参数变化，将触发将此节点的共识拓扑改变的操作；
	 *
	 * @param base58LedgerHash base58格式的账本哈希；
	 * @param consensusHost    激活参与方的共识Ip
	 * @param consensusPort    激活参与方的共识Port
	 * @param remoteManageHost 提供完备数据库的共识节点管理IP
	 * @param remoteManagePort 提供完备数据库的共识节点管理Port
	 * @return
	 */
	@RequestMapping(path = "/delegate/activeparticipant", method = RequestMethod.POST)
	public WebResponse activateParticipant(@RequestParam("ledgerHash") String base58LedgerHash,
										   @RequestParam("consensusHost") String consensusHost, @RequestParam("consensusPort") int consensusPort,
										   @RequestParam("remoteManageHost") String remoteManageHost,
										   @RequestParam("remoteManagePort") int remoteManagePort,
										   @RequestParam("shutdown") boolean shutdown) {
		try {
			HashDigest ledgerHash = Crypto.resolveAsHashDigest(Base58Utils.decode(base58LedgerHash));

			if (ledgerKeypairs.get(ledgerHash) == null) {
				return WebResponse.createFailureResult(-1, "[ManagementController] input ledgerhash not exist!");
			}

			LedgerRepository ledgerRepo = (LedgerRepository) ledgerQuerys.get(ledgerHash);

			LedgerBlock ledgerLatestBlock = ledgerRepo.retrieveLatestBlock();
			LedgerAdminInfo ledgerAdminInfo = ledgerRepo.getAdminInfo(ledgerLatestBlock);

			if (ledgerAdminInfo.getSettings().getConsensusProvider().equals(BFTSMART_PROVIDER)) {

				ledgerAdminInfo = ledgerRepo.getAdminInfo(ledgerRepo.retrieveLatestBlock());

				// 检查节点信息
				ParticipantNode node = getCurrentNode(ledgerAdminInfo, ledgerCurrNodes.get(ledgerHash).getAddress().toString());
				NodeSettings nodeSettings = getConsensusNodeSettings(ledgerQuerys.values(), consensusHost, consensusPort);
				if (nodeSettings != null) {
					if (!BytesUtils.equals(node.getPubKey().toBytes(), nodeSettings.getPubKey().toBytes())) {
						return WebResponse.createFailureResult(-1, String.format("[ManagementController] %s:%d already occupied!", consensusHost, consensusPort, node.getAddress().toBase58()));
					} else {
						LOGGER.info("[ManagementController] node exists and status is CONSENSUS!");
						// 节点存在且状态为激活，返回成功
						return WebResponse.createSuccessResult(null);
					}
				}

				int viewId = ((BftsmartConsensusViewSettings) getConsensusSetting(ledgerAdminInfo)).getViewId();

				if (node.getParticipantNodeState() != ParticipantNodeState.CONSENSUS) {
					LOGGER.info("[ManagementController] activate participant!");
					return activeParticipant(ledgerHash, ledgerRepo, node, ledgerAdminInfo, viewId, consensusHost, consensusPort, shutdown, remoteManageHost, remoteManagePort);
				} else {
					LOGGER.info("[ManagementController] update participant!");
					return updateParticipant(ledgerHash, ledgerRepo, node, ledgerAdminInfo, viewId, consensusHost, consensusPort, shutdown);
				}

			} else {
				// Todo
				// mq or others
				return WebResponse.createSuccessResult(null);
			}

		} catch (Exception e) {
			LOGGER.error("[ManagementController] activate new particpant failed!", e);
			return WebResponse.createFailureResult(-1, "[ManagementController] activate new particpant failed! " + e.getMessage());
		}
	}

	private WebResponse activeParticipant(HashDigest ledgerHash,
										  LedgerRepository ledgerRepo,
										  ParticipantNode node,
										  LedgerAdminInfo ledgerAdminInfo,
										  int viewId,
										  String consensusHost,
										  int consensusPort,
										  boolean shutdown,
										  String remoteManageHost,
										  int remoteManagePort) {

		Properties systemConfig = PropertiesUtils.createProperties(((BftsmartConsensusViewSettings) getConsensusSetting(ledgerAdminInfo)).getSystemConfigs());
		// 由本节点准备交易
		TransactionRequest txRequest = prepareActiveTx(ledgerHash, node, consensusHost, consensusPort + "", systemConfig);
		// 为交易添加本节点的签名信息，防止无法通过安全策略检查
		txRequest = addNodeSigner(txRequest);
		List<NodeSettings> origConsensusNodes = SearchOtherOrigConsensusNodes(ledgerRepo, node);
		// 连接原有的共识网络,把交易提交到目标账本的原有共识网络进行共识，即在原有共识网络中执行新参与方的状态激活操作
		TransactionResponse remoteTxResponse = commitTxToOrigConsensus(txRequest, systemConfig, viewId, origConsensusNodes);

		if(remoteTxResponse.isSuccess() && replayTransaction(ledgerRepo, node, remoteManageHost, remoteManagePort)) {
			try {
				View newView = updateView(ledgerRepo, consensusHost, consensusPort, ParticipantUpdateType.ACTIVE, systemConfig, viewId, origConsensusNodes);
				if (newView != null && newView.isMember(ledgerCurrNodes.get(ledgerRepo.getHash()).getId())) {
					LOGGER.info("[ManagementController] updateView SUCC!");
				} else if (newView == null) {
					throw new IllegalStateException("[ManagementController] client recv response timeout, consensus may be stalemate, please restart all nodes!");
				}
				setupServer(ledgerRepo, shutdown);
				return WebResponse.createSuccessResult(null);
			} catch (Exception e) {
				return WebResponse.createFailureResult(-1, "[ManagementController] commit tx to orig consensus, tx execute succ but view update failed, please restart all nodes and copy database for new participant node!");
			}
		}

		return WebResponse.createFailureResult(null);
	}

	private WebResponse updateParticipant(HashDigest ledgerHash,
										  LedgerRepository ledgerRepo,
										  ParticipantNode node,
										  LedgerAdminInfo ledgerAdminInfo,
										  int viewId,
										  String consensusHost,
										  int consensusPort,
										  boolean shutdown) {
		Properties systemConfig = PropertiesUtils.createProperties(((BftsmartConsensusViewSettings) getConsensusSetting(ledgerAdminInfo)).getSystemConfigs());
		// 由本节点准备交易
		TransactionRequest txRequest = prepareUpdateTx(ledgerHash, node, consensusHost, consensusPort + "", systemConfig);

		// 为交易添加本节点的签名信息，防止无法通过安全策略检查
		txRequest = addNodeSigner(txRequest);

		List<NodeSettings> origConsensusNodes = SearchOrigConsensusNodes(ledgerRepo);

		// 连接原有的共识网络,把交易提交到目标账本的原有共识网络进行共识，即在原有共识网络中执行新参与方的状态激活操作
		TransactionResponse remoteTxResponse = commitTxToOrigConsensus(txRequest, systemConfig, viewId, origConsensusNodes);

		// 保证原有共识网络账本状态与共识协议的视图更新信息一致
		if (remoteTxResponse.isSuccess()) {
			try {
				View newView = updateView(ledgerRepo, consensusHost, consensusPort, ParticipantUpdateType.UPDATE, systemConfig, viewId, origConsensusNodes);
				if (newView != null && newView.isMember(ledgerCurrNodes.get(ledgerRepo.getHash()).getId())) {
					LOGGER.info("[ManagementController] updateView success!");
				} else if (newView == null) {
					throw new IllegalStateException(
							"[ManagementController] client recv response timeout, consensus may be stalemate, please restart all nodes!");
				}
			} catch (Exception e) {
				LOGGER.error("[ManagementController] updateView exception!", e);
				return WebResponse.createFailureResult(-1,
						"[ManagementController] commit tx to orig consensus, tx execute succ but view update failed, please restart all nodes and copy database for new participant node!");
			}
		} else {
			return WebResponse.createFailureResult(-1,
					"[ManagementController] commit tx to orig consensus, tx execute failed, please retry activate participant!");
		}

		setupServer(ledgerRepo, shutdown);

		return WebResponse.createSuccessResult(null);
	}

	/**
	 * 根据IP和端口获取处于激活状态的节点NodeSettings，不存在返回null
	 *
	 * @param ledgers       账本数据库
	 * @param consensusHost 节点IP
	 * @param consensusPort 节点端口
	 * @return
	 */
	private NodeSettings getConsensusNodeSettings(Collection<LedgerQuery> ledgers, String consensusHost, int consensusPort) {

		for (LedgerQuery ledgerRepo : ledgers) {
			for (NodeSettings nodeSettings : SearchOrigConsensusNodes((LedgerRepository) ledgerRepo)) {
				String host = ((BftsmartNodeSettings) nodeSettings).getNetworkAddress().getHost();
				int port = ((BftsmartNodeSettings) nodeSettings).getNetworkAddress().getPort();

				if ((host.equals(consensusHost)) && port == consensusPort) {
					return nodeSettings;
				}
			}
		}

		return null;
	}

	private void cancelBlock(long blockGenerateTime, TransactionBatchProcessor txBatchProcessor) {
		LedgerEditor.TIMESTAMP_HOLDER.set(blockGenerateTime);
		TransactionBatchResultHandle handle = txBatchProcessor.prepare();
		handle.cancel(LEDGER_ERROR);
	}

	/**
	 * 代理交易； <br>
	 *
	 * 此方法假设当前节点是一个待移除的共识节点, 通过此方法接收一笔用于实现管理操作的交易；
	 *
	 * <p>
	 *
	 * 此方法接收到交易之后，先把交易提交到已有的共识网络执行，这个已有网络包括本节点； <br>
	 *
	 * <p>
	 * 如果操作中涉及到共识参与方的共识参数变化，将触发将此节点的共识拓扑改变的操作；
	 *
	 * @param base58LedgerHash   base58格式的账本哈希；
	 * @param participantAddress 待移除参与方的地址
	 * @return
	 */
	@RequestMapping(path = "/delegate/deactiveparticipant", method = RequestMethod.POST)
	public WebResponse deActivateParticipant(@RequestParam("ledgerHash") String base58LedgerHash,
											 @RequestParam("participantAddress") String participantAddress) {
		try {
			HashDigest ledgerHash = Crypto.resolveAsHashDigest(Base58Utils.decode(base58LedgerHash));

			// 进行一系列安全检查
			if (ledgerQuerys.get(ledgerHash) == null) {
				return WebResponse.createFailureResult(-1, "[ManagementController] input ledgerhash not exist!");
			}

			if (!ledgerCurrNodes.get(ledgerHash).getAddress().toBase58().equals(participantAddress)) {
				return WebResponse.createFailureResult(-1, "[ManagementController] deactive participant not me!");
			}

			LedgerRepository ledgerRepo = (LedgerRepository) ledgerQuerys.get(ledgerHash);
			LedgerAdminInfo ledgerAdminInfo = ledgerRepo.getAdminInfo();
			if (ledgerAdminInfo.getSettings().getConsensusProvider().equals(BFTSMART_PROVIDER)) {
				// 已经是DEACTIVATED状态
				ParticipantNode node = getCurrentNode(ledgerAdminInfo, participantAddress);
				if (node.getParticipantNodeState() == ParticipantNodeState.DEACTIVATED) {
					return WebResponse.createSuccessResult(null);
				}

				// 已经处于最小节点数环境的共识网络，不能再执行去激活操作
				List<NodeSettings> origConsensusNodes = SearchOrigConsensusNodes(ledgerRepo);
				if (origConsensusNodes.size() <= 4) {
					return WebResponse.createFailureResult(-1, "[ManagementController] in minimum number of nodes scenario, deactive op is not allowed!");
				}

				Properties systemConfig = PropertiesUtils.createProperties(((BftsmartConsensusViewSettings) getConsensusSetting(ledgerAdminInfo)).getSystemConfigs());
				int viewId = ((BftsmartConsensusViewSettings) getConsensusSetting(ledgerAdminInfo)).getViewId();
				// 由本节点准备交易
				TransactionRequest txRequest = prepareDeActiveTx(ledgerHash, node, systemConfig);
				// 为交易添加本节点的签名信息，防止无法通过安全策略检查
				txRequest = addNodeSigner(txRequest);
				// 连接原有的共识网络,把交易提交到目标账本的原有共识网络进行共识，即在原有共识网络中执行参与方的去激活操作，这个原有网络包括本节点
				TransactionResponse txResponse = commitTxToOrigConsensus(txRequest, systemConfig, viewId, origConsensusNodes);
				// 保证原有共识网络账本状态与共识协议的视图更新信息一致
				if (txResponse.isSuccess()) {
					View newView = updateView(ledgerRepo, null, -1, ParticipantUpdateType.DEACTIVE, systemConfig, viewId, origConsensusNodes);
					if (newView != null && !newView.isMember(ledgerCurrNodes.get(ledgerRepo.getHash()).getId())) {
						LOGGER.info("[ManagementController] update view success!");
						ledgerPeers.get(ledgerHash).stop();
					} else if (newView == null) {
						throw new IllegalStateException("[ManagementController] client recv response timeout, consensus may be stalemate, please restart all nodes!");
					}
					ledgerPeers.get(ledgerHash).stop();
					LOGGER.info("[ManagementController] updateView success!");
					return WebResponse.createSuccessResult(null);
				} else {
					return WebResponse.createFailureResult(-1, "[ManagementController] commit tx to orig consensus, tx execute failed, please retry deactivate participant!");
				}

			} else {
				// mq or others
				return WebResponse.createSuccessResult(null);
			}

		} catch (Exception e) {
			return WebResponse.createFailureResult(-1, "[ManagementController] deactivate participant failed!" + e);
		}
	}

	private ParticipantNode getCurrentNode(LedgerAdminInfo ledgerAdminInfo, String participantAddress) {
		for (ParticipantNode participantNode : ledgerAdminInfo.getParticipants()) {
			if (participantNode.getAddress().toString().equals(participantAddress)) {
				return participantNode;
			}
		}

		throw new IllegalStateException("[ManagementController] participant ["+ participantAddress +"] not exists");
	}

	private TransactionRequest prepareDeActiveTx(HashDigest ledgerHash, ParticipantNode node,
												 Properties systemConfig) {

		int deActiveID = node.getId();

		// organize system config properties
		Property[] properties = createDeactiveProperties(node.getPubKey(), deActiveID, systemConfig);

		TxBuilder txbuilder = new TxBuilder(ledgerHash, ledgerCryptoSettings.get(ledgerHash).getHashAlgorithm());

		// This transaction contains participant state update and settings update two
		// ops
		txbuilder.states().update(new BlockchainIdentityData(node.getPubKey()), ParticipantNodeState.DEACTIVATED);

		txbuilder.settings().update(properties);

		TransactionRequestBuilder reqBuilder = txbuilder.prepareRequest();

		reqBuilder.signAsEndpoint(new AsymmetricKeypair(ledgerKeypairs.get(ledgerHash).getPubKey(),
				ledgerKeypairs.get(ledgerHash).getPrivKey()));

		return reqBuilder.buildRequest();

	}

	private WebResponse checkLedgerDiff(LedgerRepository ledgerRepository, LedgerBlock ledgerLatestBlock, AsymmetricKeypair localKeyPair,
										String remoteManageHost, int remoteManagePort) {

		long localLatestBlockHeight = ledgerLatestBlock.getHeight();

		HashDigest localLatestBlockHash = ledgerLatestBlock.getHash();

		HashDigest ledgerHash = ledgerLatestBlock.getLedgerHash();

		TransactionBatchResultHandle handle = null;

		try (ServiceConnection httpConnection = new ServiceConnectionManager().create(new ServiceEndpoint(new NetworkAddress(remoteManageHost, remoteManagePort)))) {

			BlockchainQueryService queryService = HttpServiceAgent.createService(HttpBlockchainBrowserService.class, httpConnection, null);

			// 激活新节点时，远端管理节点最新区块高度
			long remoteLatestBlockHeight = queryService.getLedger(ledgerHash)
					.getLatestBlockHeight();

			if ((localLatestBlockHeight <= remoteLatestBlockHeight)) {
				// 检查本节点与拉取节点相同高度的区块，哈希是否一致,不一致说明其中一个节点的数据库被污染了
				HashDigest remoteBlockHash = queryService.getBlock(ledgerHash, localLatestBlockHeight).getHash();

				if (!(localLatestBlockHash.toBase58().equals(remoteBlockHash.toBase58()))) {
					throw new IllegalStateException(
							"[ManagementController] checkLedgerDiff, ledger database is inconsistent, please check ledger database!");
				}
				// 本节点与拉取节点高度一致，不需要进行交易重放
				if (localLatestBlockHeight == remoteLatestBlockHeight) {
					return WebResponse.createSuccessResult(null);
				}
			} else {
				throw new IllegalStateException(
						"[ManagementController] checkLedgerDiff, local latest block height > remote node latest block height!");
			}

			OperationHandleRegisteration opReg = new DefaultOperationHandleRegisteration();
			// 对差异进行交易重放
			for (int height = (int) localLatestBlockHeight + 1; height <= remoteLatestBlockHeight; height++) {
				TransactionBatchProcessor txbatchProcessor = new TransactionBatchProcessor(ledgerRepository, opReg);
				// transactions replay
				try {
					HashDigest pullBlockHash = queryService.getBlock(ledgerHash, height).getHash();
					long pullBlockTime = queryService.getBlock(ledgerHash, height).getTimestamp();

					// 获取区块内的增量交易
					List<LedgerTransaction> addition_transactions = getAdditionalTransactions(ledgerHash, height, remoteManageHost, remoteManagePort);

					try {
						for (LedgerTransaction ledgerTransaction : addition_transactions) {
							txbatchProcessor.schedule(ledgerTransaction.getRequest());
						}
					} catch (BlockRollbackException e) {
						txbatchProcessor.cancel(LEDGER_ERROR);
						continue;
					}

					LedgerEditor.TIMESTAMP_HOLDER.set(pullBlockTime);
					handle = txbatchProcessor.prepare();

					if (!(handle.getBlock().getHash().toBase58().equals(pullBlockHash.toBase58()))) {
						LOGGER.error(
								"[ManagementController] checkLedgerDiff, transactions replay result is inconsistent at height {}",
								height);
						throw new IllegalStateException(
								"[ManagementController] checkLedgerDiff, transactions replay, block hash result is inconsistent!");
					}

					handle.commit();

				} catch (Exception e) {
					handle.cancel(LEDGER_ERROR);
					throw new IllegalStateException(
							"[ManagementController] checkLedgerDiff, transactions replay failed!", e);
				}
			}
		} catch (Exception e) {
			LOGGER.error("[ManagementController] checkLedgerDiff error!", e);
			return WebResponse.createFailureResult(-1, "[ManagementController] checkLedgerDiff error!" + e);
		}

		return WebResponse.createSuccessResult(null);
	}

	private boolean replayTransaction(LedgerRepository ledgerRepository, ParticipantNode node, String remoteManageHost, int remoteManagePort) {
		long height = ledgerRepository.getLatestBlock().getHeight();
		HashDigest ledgerHash = ledgerRepository.getLatestBlock().getLedgerHash();
		TransactionBatchResultHandle handle = null;
		OperationHandleRegisteration opReg = new DefaultOperationHandleRegisteration();
		try (ServiceConnection httpConnection = new ServiceConnectionManager().create(new ServiceEndpoint(new NetworkAddress(remoteManageHost, remoteManagePort)))) {
			BlockchainQueryService queryService = HttpServiceAgent.createService(HttpBlockchainBrowserService.class, httpConnection, null);
			while (true) {
				boolean getout = false;
				TransactionBatchProcessor batchProcessor = new TransactionBatchProcessor(ledgerRepository, opReg);
				try {
					height ++;
					LedgerBlock block = queryService.getBlock(ledgerHash, height);
					// 获取区块内的增量交易
					List<LedgerTransaction> transactions = getAdditionalTransactions(ledgerHash, (int) height, remoteManageHost, remoteManagePort);
					try {
						for (LedgerTransaction ledgerTransaction : transactions) {
							batchProcessor.schedule(ledgerTransaction.getRequest());
							Operation[] operations = ledgerTransaction.getRequest().getTransactionContent().getOperations();
							for(Operation op:operations) {
								if(op instanceof ParticipantStateUpdateOperation) {
									ParticipantStateUpdateOperation psop = (ParticipantStateUpdateOperation) op;
									if(psop.getParticipantID().getPubKey().equals(node.getPubKey())) {
										getout = true;
									}
								}
							}
						}
					} catch (BlockRollbackException e) {
						batchProcessor.cancel(LEDGER_ERROR);
						continue;
					}

					LedgerEditor.TIMESTAMP_HOLDER.set(block.getTimestamp());
					handle = batchProcessor.prepare();

					if (!(handle.getBlock().getHash().toBase58().equals(block.getHash().toBase58()))) {
						LOGGER.error("[ManagementController] replayTransaction, transactions replay result is inconsistent at height {}", height);
						throw new IllegalStateException("[ManagementController] checkLedgerDiff, transactions replay, block hash result is inconsistent!");
					}
					handle.commit();
					LOGGER.debug("[ManagementController] replayTransaction, transactions replay result is consistent at height {}", height);
					if(getout) {
						return true;
					}
				} catch (Exception e) {
					handle.cancel(LEDGER_ERROR);
					throw new IllegalStateException("[ManagementController] replayTransaction, transactions replay failed!", e);
				}
			}
		}
	}

	private List<LedgerTransaction> getAdditionalTransactions(HashDigest ledgerHash, int height, String remoteManageHost, int remoteManagePort) {
		List<LedgerTransaction> txs = new ArrayList<>();
		int fromIndex = 0;

		String url = String.format("http://%s:%d/ledgers/%s/blocks/height/%d/txs/additional-txs/binary",
				remoteManageHost, remoteManagePort, ledgerHash.toBase58(), height);
		while (true) {
			try {
				HttpClient httpClient = HttpClients.createDefault();
				HttpPost httpPost = new HttpPost(url);
				List<BasicNameValuePair> params = new ArrayList<>();
				params.add(new BasicNameValuePair("fromIndex", fromIndex + ""));
				params.add(new BasicNameValuePair("count", "100"));
				httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
				HttpResponse response = httpClient.execute(httpPost);
				InputStream respStream = response.getEntity().getContent();
				if (null != respStream) {
					LedgerTransactions transactions = BinaryProtocol.decode(respStream);
					if (null != transactions && null != transactions.getLedgerTransactions()) {
						LedgerTransaction[] ts = transactions.getLedgerTransactions();
						fromIndex += ts.length;
						for (LedgerTransaction tx : ts) {
							txs.add(tx);
						}
						if (ts.length < 100) {
							break;
						}
					} else {
						break;
					}
				} else {
					break;
				}
			} catch (Exception e) {
				LOGGER.error("get transactions from remote error", e);
				throw new IllegalStateException("[ManagementController] get transactions from remote error!", e);
			}
		}
		return txs;

	}

	private static String keyOfNode(String pattern, int id) {
		return String.format(pattern, id);
	}

	private String createActiveView(String oldView, int id) {

		StringBuilder views = new StringBuilder(oldView);

		views.append(",");

		views.append(id);

		return views.toString();
	}

	private String createDeactiveView(String oldView, int id) {

		StringBuilder newViews = new StringBuilder("");

		String[] viewIdArray = oldView.split(",");

		for (String viewId : viewIdArray) {
			if (Integer.parseInt(viewId) != id) {
				newViews.append(viewId);
				newViews.append(",");
			}
		}
		String newView = newViews.toString();

		return newView.substring(0, newView.length() - 1);
	}

	// organize active participant related system config properties
	private Property[] createActiveProperties(String host, String port, PubKey activePubKey, int activeID,
											  Properties systemConfig) {
		int oldServerNum = Integer.parseInt(systemConfig.getProperty(SERVER_NUM_KEY));
		int oldFNum = Integer.parseInt(systemConfig.getProperty(F_NUM_KEY));
		String oldView = systemConfig.getProperty(SERVER_VIEW_KEY);

		List<Property> properties = new ArrayList<Property>();

		properties.add(new Property(keyOfNode(CONSENSUS_HOST_PATTERN, activeID), host));
		properties.add(new Property(keyOfNode(CONSENSUS_PORT_PATTERN, activeID), port));
		properties.add(new Property(keyOfNode(CONSENSUS_SECURE_PATTERN, activeID), "false"));
		properties.add(new Property(keyOfNode(PUBKEY_PATTERN, activeID), activePubKey.toBase58()));
		properties.add(new Property(SERVER_NUM_KEY,
				String.valueOf(Integer.parseInt(systemConfig.getProperty(SERVER_NUM_KEY)) + 1)));
		properties.add(new Property(PARTICIPANT_OP_KEY, "active"));
		properties.add(new Property(ACTIVE_PARTICIPANT_ID_KEY, String.valueOf(activeID)));

		if ((oldServerNum + 1) >= (3 * (oldFNum + 1) + 1)) {
			properties.add(new Property(F_NUM_KEY, String.valueOf(oldFNum + 1)));
		}
		properties.add(new Property(SERVER_VIEW_KEY, createActiveView(oldView, activeID)));

		return properties.toArray(new Property[properties.size()]);
	}

	// organize active participant related system config properties
	private Property[] createUpdateProperties(String host, String port, PubKey activePubKey, int activeID,
											  Properties systemConfig) {
		String oldView = systemConfig.getProperty(SERVER_VIEW_KEY);

		List<Property> properties = new ArrayList<Property>();

		properties.add(new Property(keyOfNode(CONSENSUS_HOST_PATTERN, activeID), host));
		properties.add(new Property(keyOfNode(CONSENSUS_PORT_PATTERN, activeID), port));
		properties.add(new Property(keyOfNode(CONSENSUS_SECURE_PATTERN, activeID), "false"));
		properties.add(new Property(keyOfNode(PUBKEY_PATTERN, activeID), activePubKey.toBase58()));
		properties.add(new Property(PARTICIPANT_OP_KEY, "active"));
		properties.add(new Property(ACTIVE_PARTICIPANT_ID_KEY, String.valueOf(activeID)));

		properties.add(new Property(SERVER_VIEW_KEY, createActiveView(oldView, activeID)));

		return properties.toArray(new Property[properties.size()]);
	}

	// organize deactive participant related system config properties
	private Property[] createDeactiveProperties(PubKey deActivePubKey, int deActiveID, Properties systemConfig) {
		int oldServerNum = Integer.parseInt(systemConfig.getProperty(SERVER_NUM_KEY));
		int oldFNum = Integer.parseInt(systemConfig.getProperty(F_NUM_KEY));
		String oldView = systemConfig.getProperty(SERVER_VIEW_KEY);

		List<Property> properties = new ArrayList<Property>();

		properties.add(new Property(SERVER_NUM_KEY,
				String.valueOf(Integer.parseInt(systemConfig.getProperty(SERVER_NUM_KEY)) - 1)));

		if ((oldServerNum - 1) < (3 * oldFNum + 1)) {
			properties.add(new Property(F_NUM_KEY, String.valueOf(oldFNum - 1)));
		}
		properties.add(new Property(SERVER_VIEW_KEY, createDeactiveView(oldView, deActiveID)));

		properties.add(new Property(PARTICIPANT_OP_KEY, "deactive"));

		properties.add(new Property(DEACTIVE_PARTICIPANT_ID_KEY, String.valueOf(deActiveID)));

		return properties.toArray(new Property[properties.size()]);
	}

	// 在指定的账本上准备一笔激活参与方状态及系统配置参数的操作
	private TransactionRequest prepareActiveTx(HashDigest ledgerHash, ParticipantNode node, String host,
											   String port, Properties systemConfig) {

		int activeID = node.getId();

		// organize system config properties
		Property[] properties = createActiveProperties(host, port, node.getPubKey(), activeID, systemConfig);

		TxBuilder txbuilder = new TxBuilder(ledgerHash, ledgerCryptoSettings.get(ledgerHash).getHashAlgorithm());

		// This transaction contains participant state update and settings update two
		// ops
		txbuilder.states().update(new BlockchainIdentityData(node.getPubKey()), ParticipantNodeState.CONSENSUS);

		txbuilder.settings().update(properties);

		TransactionRequestBuilder reqBuilder = txbuilder.prepareRequest();

		reqBuilder.signAsEndpoint(new AsymmetricKeypair(ledgerKeypairs.get(ledgerHash).getPubKey(),
				ledgerKeypairs.get(ledgerHash).getPrivKey()));

		return reqBuilder.buildRequest();

	}

	// 在指定的账本上准备一笔激活参与方状态及系统配置参数的操作
	private TransactionRequest prepareUpdateTx(HashDigest ledgerHash, ParticipantNode node, String host,
											   String port, Properties systemConfig) {

		int activeID = node.getId();

		// organize system config properties
		Property[] properties = createUpdateProperties(host, port, node.getPubKey(), activeID, systemConfig);

		TxBuilder txbuilder = new TxBuilder(ledgerHash, ledgerCryptoSettings.get(ledgerHash).getHashAlgorithm());

		// This transaction contains participant state update and settings update two
		// ops
		txbuilder.states().update(new BlockchainIdentityData(node.getPubKey()), ParticipantNodeState.CONSENSUS);

		txbuilder.settings().update(properties);

		TransactionRequestBuilder reqBuilder = txbuilder.prepareRequest();

		reqBuilder.signAsEndpoint(new AsymmetricKeypair(ledgerKeypairs.get(ledgerHash).getPubKey(),
				ledgerKeypairs.get(ledgerHash).getPrivKey()));

		return reqBuilder.buildRequest();

	}

	// 加载本参与方的公私钥对身份信息
	private AsymmetricKeypair loadIdentity(ParticipantNode currentNode, BindingConfig bindingConfig) {

		PubKey pubKey = currentNode.getPubKey();

		PrivKey privKey = null;
		String pk = bindingConfig.getParticipant().getPk();
		String pwd = bindingConfig.getParticipant().getPassword();
		String pkPath = bindingConfig.getParticipant().getPkPath();
		if(!StringUtils.isEmpty(pk) && !StringUtils.isEmpty(pwd)) {
			try{
				privKey = KeyGenUtils.decodePrivKey(pk, pwd);
			} catch (Exception e) {}
		} else if(!StringUtils.isEmpty(pkPath)) {
			if(!StringUtils.isEmpty(pwd)) {
				try{
					privKey = KeyGenUtils.decodePrivKey(pk, pwd);
				} catch (Exception e) {}
				if(null == privKey) {
					try {
						privKey = CertificateUtils.parsePrivKey(pubKey.getAlgorithm(), new File(pkPath), pwd);
					}catch (Exception e) {}
				}
			} else {
				try {
					privKey = CertificateUtils.parsePrivKey(pubKey.getAlgorithm(), new File(pkPath));
				}catch (Exception e) {}
			}
		}
		if(null == privKey) {
			LOGGER.error("Error keypair or certificate configurations in ledger-binding.conf, participant node: {}", currentNode.getAddress());
		}
		return new AsymmetricKeypair(pubKey, privKey);

	}

	// 视图更新完成，启动共识节点
	private void setupServer(LedgerRepository ledgerRepository, boolean shutdown) {
		try {

			// 关闭旧的server
			NodeServer server = ledgerPeers.get(ledgerRepository.getHash());
			if (null != server) {
				LOGGER.info("[ManagementController] stop old server");
				server.stop();
			}

			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				LOGGER.error("[ManagementController] sleep InterruptedException", e);
			}

			if(shutdown) {
				LOGGER.info("[ManagementController] shutdown server in this ip");
				return;
			}

			ParticipantNode currentNode = ledgerCurrNodes.get(ledgerRepository.getHash());

			LedgerAdminInfo ledgerAdminAccount = ledgerRepository
					.getAdminInfo(ledgerRepository.getBlock(ledgerRepository.retrieveLatestBlockHeight()));

			// load provider;
			ConsensusProvider provider = getProvider(ledgerAdminAccount);

			// load consensus setting;
			ConsensusViewSettings csSettings = getConsensusSetting(ledgerAdminAccount);

			ServerSettings serverSettings = provider.getServerFactory().buildServerSettings(
					ledgerRepository.getHash().toBase58(), csSettings, currentNode.getAddress().toBase58());

			((LedgerStateManager) consensusStateManager).setLatestStateId(ledgerRepository.retrieveLatestBlockHeight());

			Storage consensusRuntimeStorage = getConsensusRuntimeStorage(ledgerRepository.getHash());
			server = provider.getServerFactory().setupServer(serverSettings, consensusMessageHandler,
					consensusStateManager, consensusRuntimeStorage);

			ledgerPeers.put(ledgerRepository.getHash(), server);

			runRealm(server);

			LOGGER.info("[ManagementController] setupServer success!");
		} catch (Exception e) {
			throw new StartServerException("[ManagementController] start server fail exception", e);
		}

	}

	// 通知原有的共识网络更新共识的视图ID
	private View updateView(LedgerRepository ledgerRepository, String consensusHost, int consensusPort, ParticipantUpdateType participantUpdateType,
							Properties systemConfig, int viewId, List<NodeSettings> origConsensusNodes) {
		ParticipantNode currNode = ledgerCurrNodes.get(ledgerRepository.getHash());

		LOGGER.info("ManagementController start updateView operation!");

		try {
			ServiceProxy peerProxy = createPeerProxy(systemConfig, viewId, origConsensusNodes);

			Reconfiguration reconfiguration = new Reconfiguration(peerProxy.getProcessId(), peerProxy);

			if (participantUpdateType == ParticipantUpdateType.ACTIVE) {
				// addServer的第一个参数指待加入共识的新参与方的编号
				reconfiguration.addServer(currNode.getId(), consensusHost, consensusPort);
			} else if (participantUpdateType == ParticipantUpdateType.DEACTIVE) {
				// 参数为待移除共识节点的id
				reconfiguration.removeServer(currNode.getId());
			} else if (participantUpdateType == ParticipantUpdateType.UPDATE) {
				// 共识参数修改，先移除后添加
				reconfiguration.removeServer(currNode.getId());
				reconfiguration.addServer(currNode.getId(), consensusHost, consensusPort);
			} else {
				throw new IllegalArgumentException("[ManagementController] op type error!");
			}

			// 执行更新目标共识网络的视图ID
			ReconfigureReply reconfigureReply = reconfiguration.execute();

			peerProxy.close();

			// 返回新视图
			return reconfigureReply.getView();

		} catch (Exception e) {
			throw new ViewUpdateException("[ManagementController] view update fail exception!", e);
		}
	}

	private TransactionRequest addNodeSigner(TransactionRequest txRequest) {
		TxRequestMessage txMessage = new TxRequestMessage(txRequest);

		HashDigest ledgerHash = txRequest.getTransactionContent().getLedgerHash();
		AsymmetricKeypair peerKeypair = ledgerKeypairs.get(ledgerHash);
		DigitalSignature nodeSigner = SignatureUtils.sign(ledgerCryptoSettings.get(ledgerHash).getHashAlgorithm(),
				txRequest.getTransactionContent(), peerKeypair);

		txMessage.addNodeSignatures(nodeSigner);

		// 计算交易哈希；
//		byte[] nodeRequestBytes = BinaryProtocol.encode(txMessage, TransactionRequest.class);
//		HashFunction hashFunc = Crypto.getHashFunction(cryptoSetting.getHashAlgorithm());
//		HashDigest txHash = hashFunc.hash(nodeRequestBytes);
//		txMessage.setTransactionHash(txHash);

		return txMessage;
	}

	private TransactionResponse txResponseWrapper(TransactionResponse txResponse) {
		return new TxResponseMessage(txResponse, null);
	}

	private ServiceProxy createPeerProxy(Properties systemConfig, int viewId, List<NodeSettings> origConsensusNodes) {

		HostsConfig hostsConfig;
		List<HostsConfig.Config> configList = new ArrayList<>();
		List<NodeNetwork> nodeAddresses = new ArrayList<>();

		try {

			int[] origConsensusProcesses = new int[origConsensusNodes.size()];

			for (int i = 0; i < origConsensusNodes.size(); i++) {
				BftsmartNodeSettings node = (BftsmartNodeSettings) origConsensusNodes.get(i);
				origConsensusProcesses[i] = node.getId();
				configList.add(new HostsConfig.Config(node.getId(), node.getNetworkAddress().getHost(),
						node.getNetworkAddress().getPort(), -1));
				nodeAddresses.add(
						new NodeNetwork(node.getNetworkAddress().getHost(), node.getNetworkAddress().getPort(), -1));
			}

			// 构建共识的代理客户端需要的主机配置和系统参数配置结构
			hostsConfig = new HostsConfig(configList.toArray(new HostsConfig.Config[configList.size()]));

			Properties tempSystemConfig = (Properties) systemConfig.clone();

			// 构建tom 配置
			TOMConfiguration tomConfig = new TOMConfiguration(-(new Random().nextInt(Integer.MAX_VALUE-2) - 1), tempSystemConfig, hostsConfig);

			View view = new View(viewId, origConsensusProcesses, tomConfig.getF(),
					nodeAddresses.toArray(new NodeNetwork[nodeAddresses.size()]));

			LOGGER.info("ManagementController start updateView operation!, current view : {}", view.toString());

			// 构建共识的代理客户端，连接目标共识节点，并递交交易进行共识过程
			return new ServiceProxy(tomConfig, new MemoryBasedViewStorage(view), null, null);

		} catch (Exception e) {
			e.printStackTrace();
			throw new CreateProxyClientException("[ManagementController] create proxy client exception!");
		}

	}

	// SDK 通过Peer节点转发交易到远端的共识网络
	private TransactionResponse commitTxToOrigConsensus(TransactionRequest txRequest, Properties systemConfig, int viewId, List<NodeSettings> origConsensusNodes) {
		TransactionResponse transactionResponse = new TxResponseMessage();

		ServiceProxy peerProxy = createPeerProxy(systemConfig, viewId, origConsensusNodes);

		byte[] result = peerProxy.invokeOrdered(BinaryProtocol.encode(txRequest, TransactionRequest.class));

		if (result == null) {
			((TxResponseMessage) transactionResponse).setExecutionState(TransactionState.CONSENSUS_NO_REPLY_ERROR);
			return transactionResponse;
		}

		peerProxy.close();

		return txResponseWrapper(BinaryProtocol.decode(result));
	}

	private ConsensusProvider getProvider(LedgerAdminInfo ledgerAdminInfo) {
		// load provider;
		String consensusProvider = ledgerAdminInfo.getSettings().getConsensusProvider();
		ConsensusProvider provider = ConsensusProviders.getProvider(consensusProvider);

		return provider;

	}

	private ConsensusViewSettings getConsensusSetting(LedgerAdminInfo ledgerAdminInfo) {

		ConsensusProvider provider = getProvider(ledgerAdminInfo);

		// load consensus setting
		Bytes csSettingBytes = ledgerAdminInfo.getSettings().getConsensusSetting();
		ConsensusViewSettings csSettings = provider.getSettingsFactory().getConsensusSettingsEncoder()
				.decode(csSettingBytes.toBytes());

		return csSettings;
	}

	ParticipantNodeState getParticipantState(String address, LedgerAdminInfo ledgerAdminInfo) {
		ParticipantNodeState nodeState = null;
		for (ParticipantNode participantNode : ledgerAdminInfo.getParticipants()) {
			if (participantNode.getAddress().toString().equals(address)) {
				nodeState = participantNode.getParticipantNodeState();
				break;
			}
		}

		return nodeState;
	}

	// 查找原有共识网络中的其他共识节点信息
	private List<NodeSettings> SearchOtherOrigConsensusNodes(LedgerRepository ledgerRepository, ParticipantNode currentNode) {
		List<NodeSettings> origConsensusNodes = new ArrayList<>();
		LedgerAdminInfo ledgerAdminInfo = ledgerRepository.getAdminInfo(ledgerRepository.retrieveLatestBlock());
		// load consensus setting
		ConsensusViewSettings csSettings = getConsensusSetting(ledgerAdminInfo);

		NodeSettings[] nodeSettingsArray = csSettings.getNodes();
		for (NodeSettings nodeSettings : nodeSettingsArray) {
			// 排除不处于激活状态的共识节点
			if (getParticipantState(nodeSettings.getAddress(), ledgerAdminInfo) != ParticipantNodeState.CONSENSUS) {
				continue;
			}

			// 排除当前节点
			if (currentNode.getAddress().toBase58().equals(nodeSettings.getAddress())) {
				continue;
			}

			origConsensusNodes.add(nodeSettings);
		}
		return origConsensusNodes;
	}

	// 查找原有共识网络中的共识节点信息
	private List<NodeSettings> SearchOrigConsensusNodes(LedgerRepository ledgerRepository) {
		List<NodeSettings> origConsensusNodes = new ArrayList<>();
		LedgerAdminInfo ledgerAdminInfo = ledgerRepository.getAdminInfo(ledgerRepository.retrieveLatestBlock());
		// load consensus setting
		ConsensusViewSettings csSettings = getConsensusSetting(ledgerAdminInfo);

		NodeSettings[] nodeSettingsArray = csSettings.getNodes();
		for (NodeSettings nodeSettings : nodeSettingsArray) {
			// 排除不处于激活状态的共识节点
			if (getParticipantState(nodeSettings.getAddress(), ledgerAdminInfo) != ParticipantNodeState.CONSENSUS) {
				continue;
			}

			origConsensusNodes.add(nodeSettings);
		}
		return origConsensusNodes;
	}

	private static ThreadPoolExecutor initLedgerLoadExecutor(int coreSize) {
		ThreadFactory threadFactory = new ThreadFactoryBuilder().setNameFormat("consensus-server-%d").build();

		return new ThreadPoolExecutor(coreSize, coreSize, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>(1024),
				threadFactory, new ThreadPoolExecutor.AbortPolicy());
	}

	// 节点更新类型
	private enum ParticipantUpdateType {
		// 激活
		ACTIVE,
		// 移除
		DEACTIVE,
		// 更新
		UPDATE,
	}
}
