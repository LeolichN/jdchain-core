package com.jd.blockchain.gateway.web;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.jd.blockchain.contract.ContractProcessor;
import com.jd.blockchain.contract.OnLineContractProcessor;
import com.jd.blockchain.crypto.AddressEncoding;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.crypto.KeyGenUtils;
import com.jd.blockchain.crypto.PubKey;
import com.jd.blockchain.gateway.exception.BlockNonExistentException;
import com.jd.blockchain.gateway.service.DataRetrievalService;
import com.jd.blockchain.gateway.service.GatewayQueryService;
import com.jd.blockchain.gateway.service.PeerConnectionManager;
import com.jd.blockchain.gateway.service.settings.LedgerBaseSettings;
import com.jd.blockchain.ledger.BlockchainIdentity;
import com.jd.blockchain.ledger.ContractInfo;
import com.jd.blockchain.ledger.DataAccountInfo;
import com.jd.blockchain.ledger.Event;
import com.jd.blockchain.ledger.KVInfoVO;
import com.jd.blockchain.ledger.LedgerAdminInfo;
import com.jd.blockchain.ledger.LedgerBlock;
import com.jd.blockchain.ledger.LedgerInfo;
import com.jd.blockchain.ledger.LedgerMetadata;
import com.jd.blockchain.ledger.LedgerTransaction;
import com.jd.blockchain.ledger.ParticipantNode;
import com.jd.blockchain.ledger.PrivilegeSet;
import com.jd.blockchain.ledger.TransactionState;
import com.jd.blockchain.ledger.TypedKVEntry;
import com.jd.blockchain.ledger.UserInfo;
import com.jd.blockchain.ledger.UserPrivilegeSet;
import com.jd.blockchain.sdk.BlockchainExtendQueryService;
import com.jd.blockchain.sdk.ContractSettings;
import com.jd.blockchain.utils.BaseConstant;
import com.jd.blockchain.utils.ConsoleUtils;

@RestController
@RequestMapping(path = "/")
public class BlockBrowserController implements BlockchainExtendQueryService {

	private static final ContractProcessor CONTRACT_PROCESSOR = OnLineContractProcessor.getInstance();

	private final Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired
	private PeerConnectionManager peerService;

	@Autowired
	private GatewayQueryService gatewayQueryService;

	@Autowired
	private DataRetrievalService dataRetrievalService;

	private String dataRetrievalUrl;
	private String schemaRetrievalUrl;

	private static final long BLOCK_MAX_DISPLAY = 3L;

	private static final long GENESIS_BLOCK_HEIGHT = 0L;

	@RequestMapping(method = RequestMethod.GET, path = "ledgers")
	@Override
	public HashDigest[] getLedgerHashs() {
		return peerService.getQueryService().getLedgerHashs();
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}")
	@Override
	public LedgerInfo getLedger(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/admininfo")
	@Override
	public LedgerAdminInfo getLedgerAdminInfo(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getLedgerAdminInfo(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/participants")
	@Override
	public ParticipantNode[] getConsensusParticipants(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getConsensusParticipants(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/metadata")
	@Override
	public LedgerMetadata getLedgerMetadata(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getLedgerMetadata(ledgerHash);
	}

    @RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/settings")
    public LedgerBaseSettings getLedgerInitSettings(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
	    return gatewayQueryService.getLedgerBaseSettings(ledgerHash);
    }

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks")
	public LedgerBlock[] getBlocks(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		LedgerInfo ledgerInfo = peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
		long maxBlockHeight = ledgerInfo.getLatestBlockHeight();
		List<LedgerBlock> ledgerBlocks = new ArrayList<>();
		for (long blockHeight = maxBlockHeight; blockHeight > GENESIS_BLOCK_HEIGHT; blockHeight--) {
			LedgerBlock ledgerBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHeight);
			ledgerBlocks.add(0, ledgerBlock);
			if (ledgerBlocks.size() == BLOCK_MAX_DISPLAY) {
				break;
			}
		}
		// 最后增加创世区块
		LedgerBlock genesisBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, GENESIS_BLOCK_HEIGHT);
		ledgerBlocks.add(0, genesisBlock);
		LedgerBlock[] blocks = new LedgerBlock[ledgerBlocks.size()];
		ledgerBlocks.toArray(blocks);
		return blocks;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}")
	@Override
	public LedgerBlock getBlock(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		// 获取最新区块高度
		LedgerBlock latestBlock = getLatestBlock(ledgerHash);
		if (blockHeight >= latestBlock.getHeight() || blockHeight < 0) {
			return latestBlock;
		} else {
			return peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHeight);
		}
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}")
	@Override
	public LedgerBlock getBlock(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		return peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/txs/count")
	@Override
	public long getTransactionCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		return peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, blockHeight);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/txs/count")
	@Override
	public long getTransactionCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		return peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, blockHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/txs/count")
	@Override
	public long getTransactionTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getTransactionTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/accounts/count")
	@Override
	public long getDataAccountCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		return peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, blockHeight);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/accounts/count")
	@Override
	public long getDataAccountCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		return peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, blockHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/accounts/count")
	@Override
	public long getDataAccountTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getDataAccountTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/users/count")
	@Override
	public long getUserCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		return peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, blockHeight);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/users/count")
	@Override
	public long getUserCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		return peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, blockHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/users/count")
	@Override
	public long getUserTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getUserTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/contracts/count")
	@Override
	public long getContractCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		return peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, blockHeight);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/contracts/count")
	@Override
	public long getContractCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		return peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, blockHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts/count")
	@Override
	public long getContractTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getContractTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/txs")
	@Override
	public LedgerTransaction[] getTransactions(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight,
			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getTransactions(ledgerHash, blockHeight, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/txs")
	@Override
	public LedgerTransaction[] getTransactions(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
											   @PathVariable(name = "blockHash") HashDigest blockHash,
											   @RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
											   @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getTransactions(ledgerHash, blockHash, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/txs/additional-txs")
	@Override
	public LedgerTransaction[] getAdditionalTransactions(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
														 @PathVariable(name = "blockHeight") long blockHeight,
														 @RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
														 @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getAdditionalTransactions(ledgerHash, blockHeight, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/txs/additional-txs")
	@Override
	public LedgerTransaction[] getAdditionalTransactions(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
														 @PathVariable(name = "blockHash") HashDigest blockHash,
														 @RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
														 @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getAdditionalTransactions(ledgerHash, blockHash, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/txs/hash/{contentHash}")
	@Override
	public LedgerTransaction getTransactionByContentHash(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "contentHash") HashDigest contentHash) {
		return peerService.getQueryService(ledgerHash).getTransactionByContentHash(ledgerHash, contentHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/txs/state/{contentHash}")
	@Override
	public TransactionState getTransactionStateByContentHash(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "contentHash") HashDigest contentHash) {
		return peerService.getQueryService(ledgerHash).getTransactionStateByContentHash(ledgerHash, contentHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/users/address/{address}")
	@Override
	public UserInfo getUser(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "address") String address) {
		return peerService.getQueryService(ledgerHash).getUser(ledgerHash, address);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/accounts/address/{address}")
	@Override
	public DataAccountInfo getDataAccount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										  @PathVariable(name = "address") String address) {

		return peerService.getQueryService(ledgerHash).getDataAccount(ledgerHash, address);
	}

	@RequestMapping(method = { RequestMethod.GET,
			RequestMethod.POST }, path = "ledgers/{ledgerHash}/accounts/{address}/entries")
	@Override
	public TypedKVEntry[] getDataEntries(@PathVariable("ledgerHash") HashDigest ledgerHash,
			@PathVariable("address") String address, @RequestParam("keys") String... keys) {
		return peerService.getQueryService(ledgerHash).getDataEntries(ledgerHash, address, keys);
	}

	@RequestMapping(method = { RequestMethod.GET,
			RequestMethod.POST }, path = "ledgers/{ledgerHash}/accounts/{address}/entries-version")
	@Override
	public TypedKVEntry[] getDataEntries(@PathVariable("ledgerHash") HashDigest ledgerHash,
			@PathVariable("address") String address, @RequestBody KVInfoVO kvInfoVO) {
		return peerService.getQueryService(ledgerHash).getDataEntries(ledgerHash, address, kvInfoVO);
	}

	@RequestMapping(method = { RequestMethod.GET,
			RequestMethod.POST }, path = "ledgers/{ledgerHash}/accounts/address/{address}/entries")
	@Override
	public TypedKVEntry[] getDataEntries(@PathVariable("ledgerHash") HashDigest ledgerHash,
			@PathVariable("address") String address,
			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getDataEntries(ledgerHash, address, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/accounts/address/{address}/entries/count")
	@Override
	public long getDataEntriesTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "address") String address) {
		return peerService.getQueryService(ledgerHash).getDataEntriesTotalCount(ledgerHash, address);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts/address/{address}")
	public ContractSettings getContractSettings(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "address") String address) {
		ContractInfo contractInfo = peerService.getQueryService(ledgerHash).getContract(ledgerHash, address);
		return contractSettings(contractInfo);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts/address/{address}/version/{version}")
	public ContractSettings getContractSettingsByVersion(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
														 @PathVariable(name = "address") String address, @PathVariable(name = "version") long version) {
		ContractInfo contractInfo = peerService.getQueryService(ledgerHash).getContract(ledgerHash, address, version);
		return contractSettings(contractInfo);
	}


	private ContractSettings contractSettings(ContractInfo contractInfo) {
		if(null == contractInfo) {
			return null;
		}
		ContractSettings contractSettings = new ContractSettings(contractInfo.getAddress(), contractInfo.getPubKey(),
				contractInfo.getHeaderRootHash(), contractInfo.getDataRootHash());
		byte[] chainCodeBytes = contractInfo.getChainCode();
		try {
			// 将反编译chainCode
			String mainClassJava = CONTRACT_PROCESSOR.decompileEntranceClass(chainCodeBytes);
			contractSettings.setChainCode(mainClassJava);
			contractSettings.setChainCodeVersion(contractInfo.getChainCodeVersion());
		} catch (Exception e) {
			// 打印日志
			logger.error(String.format("Decompile contract[%s] error !!!",
					contractInfo.getAddress().toBase58()), e);
		}
		return contractSettings;
	}

//    @RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts/address/{address}")
	@Override
	public ContractInfo getContract(HashDigest ledgerHash, String address) {
		return peerService.getQueryService(ledgerHash).getContract(ledgerHash, address);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/system/names/{eventName}")
	@Override
	public Event[] getSystemEvents(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
								   @PathVariable(name = "eventName") String eventName,
								   @RequestParam(name = "fromSequence", required = false, defaultValue = "0") long fromSequence,
								   @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getEventListener().getSystemEvents(ledgerHash, eventName, fromSequence, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/system/names/count")
	@Override
	public long getSystemEventNameTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getSystemEventNameTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/system/names")
	@Override
	public String[] getSystemEventNames(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
										@RequestParam(name = "maxCount", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getSystemEventNames(ledgerHash, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/system/names/{eventName}/latest")
	@Override
	public Event getLatestEvent(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
								@PathVariable(name = "eventName") String eventName) {
		return peerService.getQueryService(ledgerHash).getLatestEvent(ledgerHash, eventName);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/system/names/{eventName}/count")
	@Override
	public long getSystemEventsTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										  @PathVariable(name = "eventName") String eventName) {
		return peerService.getQueryService(ledgerHash).getSystemEventsTotalCount(ledgerHash, eventName);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts")
	@Override
	public BlockchainIdentity[] getUserEventAccounts(@PathVariable(name = "ledgerHash")  HashDigest ledgerHash,
													 @RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
													 @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getUserEventAccounts(ledgerHash, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}")
	@Override
	public BlockchainIdentity getUserEventAccount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
												  @PathVariable(name = "address") String address) {
		return peerService.getQueryService(ledgerHash).getUserEventAccount(ledgerHash, address);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/count")
	@Override
	public long getUserEventAccountTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getUserEventAccountTotalCount(ledgerHash);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}/names/count")
	@Override
	public long getUserEventNameTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										   @PathVariable(name = "address") String address) {
		return peerService.getQueryService(ledgerHash).getUserEventNameTotalCount(ledgerHash, address);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}/names")
	@Override
	public String[] getUserEventNames(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
									  @PathVariable(name = "address") String address,
									 @RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
									 @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getQueryService(ledgerHash).getUserEventNames(ledgerHash, address, fromIndex, count);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}/names/{eventName}/latest")
	@Override
	public Event getLatestEvent(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
								@PathVariable(name = "address") String address,
								@PathVariable(name = "eventName") String eventName) {
		return peerService.getQueryService(ledgerHash).getLatestEvent(ledgerHash, address, eventName);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}/names/{eventName}/count")
	@Override
	public long getUserEventsTotalCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										@PathVariable(name = "address") String address,
										@PathVariable(name = "eventName") String eventName) {
		return peerService.getQueryService(ledgerHash).getUserEventsTotalCount(ledgerHash, address, eventName);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/events/user/accounts/{address}/names/{eventName}")
	@Override
	public Event[] getUserEvents(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
								 @PathVariable(name = "address") String address,
								 @PathVariable(name = "eventName") String eventName,
								 @RequestParam(name = "fromSequence", required = false, defaultValue = "0") long fromSequence,
								 @RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return peerService.getEventListener().getUserEvents(ledgerHash, address, eventName, fromSequence, count);
	}

	@Override
	public ContractInfo getContract(HashDigest ledgerHash, String address, long version) {
		return peerService.getQueryService(ledgerHash).getContract(ledgerHash, address, version);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/latest")
	@Override
	public LedgerBlock getLatestBlock(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		long latestBlockHeight = peerService.getQueryService(ledgerHash).getLedger(ledgerHash).getLatestBlockHeight();
		return peerService.getQueryService(ledgerHash).getBlock(ledgerHash, latestBlockHeight);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/txs/additional-count")
	@Override
	public long getAdditionalTransactionCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		// 获取某个区块的交易总数
		long currentBlockTxCount = peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, blockHeight);
		if (blockHeight == GENESIS_BLOCK_HEIGHT) {
			return currentBlockTxCount;
		}
		long lastBlockHeight = blockHeight - 1;
		long lastBlockTxCount = peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, lastBlockHeight);
		// 当前区块交易数减上个区块交易数
		return currentBlockTxCount - lastBlockTxCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/txs/additional-count")
	@Override
	public long getAdditionalTransactionCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		LedgerBlock currentBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHash);
		long currentBlockTxCount = peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, blockHash);
		if (currentBlock.getHeight() == GENESIS_BLOCK_HEIGHT) {
			return currentBlockTxCount;
		}
		HashDigest previousHash = currentBlock.getPreviousHash();
		long lastBlockTxCount = peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, previousHash);
		// 当前区块交易数减上个区块交易数
		return currentBlockTxCount - lastBlockTxCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/txs/additional-count")
	@Override
	public long getAdditionalTransactionCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		LedgerInfo ledgerInfo = peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
		long maxBlockHeight = ledgerInfo.getLatestBlockHeight();
		long totalCount = peerService.getQueryService(ledgerHash).getTransactionTotalCount(ledgerHash);
		if (maxBlockHeight == GENESIS_BLOCK_HEIGHT) { // 只有一个创世区块
			return totalCount;
		}
		long lastTotalCount = peerService.getQueryService(ledgerHash).getTransactionCount(ledgerHash, maxBlockHeight - 1);
		return totalCount - lastTotalCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/accounts/additional-count")
	@Override
	public long getAdditionalDataAccountCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		long currentDaCount = peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, blockHeight);
		if (blockHeight == GENESIS_BLOCK_HEIGHT) {
			return currentDaCount;
		}
		long lastBlockHeight = blockHeight - 1;
		long lastDaCount = peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, lastBlockHeight);
		return currentDaCount - lastDaCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/accounts/additional-count")
	@Override
	public long getAdditionalDataAccountCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		LedgerBlock currentBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHash);
		long currentBlockDaCount = peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, blockHash);
		if (currentBlock.getHeight() == GENESIS_BLOCK_HEIGHT) {
			return currentBlockDaCount;
		}
		HashDigest previousHash = currentBlock.getPreviousHash();
		long lastBlockDaCount = peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, previousHash);
		// 当前区块数据账户数量减上个区块数据账户数量
		return currentBlockDaCount - lastBlockDaCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/accounts/additional-count")
	@Override
	public long getAdditionalDataAccountCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		LedgerInfo ledgerInfo = peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
		long maxBlockHeight = ledgerInfo.getLatestBlockHeight();
		long totalCount = peerService.getQueryService(ledgerHash).getDataAccountTotalCount(ledgerHash);
		if (maxBlockHeight == GENESIS_BLOCK_HEIGHT) { // 只有一个创世区块
			return totalCount;
		}
		long lastTotalCount = peerService.getQueryService(ledgerHash).getDataAccountCount(ledgerHash, maxBlockHeight - 1);
		return totalCount - lastTotalCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/users/additional-count")
	@Override
	public long getAdditionalUserCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		long currentUserCount = peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, blockHeight);
		if (blockHeight == GENESIS_BLOCK_HEIGHT) {
			return currentUserCount;
		}
		long lastBlockHeight = blockHeight - 1;
		long lastUserCount = peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, lastBlockHeight);
		return currentUserCount - lastUserCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/users/additional-count")
	@Override
	public long getAdditionalUserCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		LedgerBlock currentBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHash);
		long currentBlockUserCount = peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, blockHash);
		if (currentBlock.getHeight() == GENESIS_BLOCK_HEIGHT) {
			return currentBlockUserCount;
		}
		HashDigest previousHash = currentBlock.getPreviousHash();
		long lastBlockUserCount = peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, previousHash);
		// 当前区块用户数量减上个区块用户数量
		return currentBlockUserCount - lastBlockUserCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/users/additional-count")
	@Override
	public long getAdditionalUserCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		LedgerInfo ledgerInfo = peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
		long maxBlockHeight = ledgerInfo.getLatestBlockHeight();
		long totalCount = peerService.getQueryService(ledgerHash).getUserTotalCount(ledgerHash);
		if (maxBlockHeight == GENESIS_BLOCK_HEIGHT) { // 只有一个创世区块
			return totalCount;
		}
		long lastTotalCount = peerService.getQueryService(ledgerHash).getUserCount(ledgerHash, maxBlockHeight - 1);
		return totalCount - lastTotalCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/height/{blockHeight}/contracts/additional-count")
	@Override
	public long getAdditionalContractCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHeight") long blockHeight) {
		long currentContractCount = peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, blockHeight);
		if (blockHeight == GENESIS_BLOCK_HEIGHT) {
			return currentContractCount;
		}
		long lastBlockHeight = blockHeight - 1;
		long lastContractCount = peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, lastBlockHeight);
		return currentContractCount - lastContractCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/blocks/hash/{blockHash}/contracts/additional-count")
	@Override
	public long getAdditionalContractCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@PathVariable(name = "blockHash") HashDigest blockHash) {
		LedgerBlock currentBlock = peerService.getQueryService(ledgerHash).getBlock(ledgerHash, blockHash);
		long currentBlockContractCount = peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, blockHash);
		if (currentBlock.getHeight() == GENESIS_BLOCK_HEIGHT) {
			return currentBlockContractCount;
		}
		HashDigest previousHash = currentBlock.getPreviousHash();
		long lastBlockContractCount = peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, previousHash);
		// 当前区块合约数量减上个区块合约数量
		return currentBlockContractCount - lastBlockContractCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts/additional-count")
	@Override
	public long getAdditionalContractCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		LedgerInfo ledgerInfo = peerService.getQueryService(ledgerHash).getLedger(ledgerHash);
		long maxBlockHeight = ledgerInfo.getLatestBlockHeight();
		long totalCount = peerService.getQueryService(ledgerHash).getContractTotalCount(ledgerHash);
		if (maxBlockHeight == GENESIS_BLOCK_HEIGHT) { // 只有一个创世区块
			return totalCount;
		}
		long lastTotalCount = peerService.getQueryService(ledgerHash).getContractCount(ledgerHash, maxBlockHeight - 1);
		return totalCount - lastTotalCount;
	}

	@RequestMapping(method = RequestMethod.GET, path = "utils/pubkey/{pubkey}/addr")
	public String getAddrByPubKey(@PathVariable(name = "pubkey") String strPubKey) {
		PubKey pubKey = KeyGenUtils.decodePubKey(strPubKey);
		return AddressEncoding.generateAddress(pubKey).toBase58();
	}

	@RequestMapping(method = RequestMethod.GET, value = "ledgers/{ledgerHash}/**/search")
	public Object dataRetrieval(@PathVariable(name = "ledgerHash") HashDigest ledgerHash, HttpServletRequest request) {
		String result;
		if (dataRetrievalUrl == null || dataRetrievalUrl.length() <= 0) {
			result = "{'message':'OK','data':'" + "data.retrieval.url is empty" + "'}";
		} else {
			String queryParams = request.getQueryString() == null ? "" : request.getQueryString();
			String fullQueryUrl = new StringBuffer(dataRetrievalUrl).append(request.getRequestURI())
					.append(BaseConstant.DELIMETER_QUESTION).append(queryParams).toString();
			try {
				result = dataRetrievalService.retrieval(fullQueryUrl);
				ConsoleUtils.info("request = {%s} \r\n result = {%s} \r\n", fullQueryUrl, result);
			} catch (Exception e) {
				result = "{'message':'OK','data':'" + e.getMessage() + "'}";
			}
		}
		return result;
	}

	/**
	 * querysql;
	 * @param request
	 * @return
	 */
	@RequestMapping(method = RequestMethod.POST, value = "schema/querysql")
	public Object queryBySql(HttpServletRequest request,@RequestBody String queryString) {
		String result;
		if (schemaRetrievalUrl == null ||  schemaRetrievalUrl.length() <= 0) {
			result = "{'message':'OK','data':'" + "schema.retrieval.url is empty" + "'}";
		} else {
			String queryParams = request.getQueryString() == null ? "": request.getQueryString();
			String fullQueryUrl = new StringBuffer(schemaRetrievalUrl)
					.append(request.getRequestURI())
					.append(BaseConstant.DELIMETER_QUESTION)
					.append(queryParams)
					.toString();
			try {
				result = dataRetrievalService.retrievalPost(fullQueryUrl,queryString);
				ConsoleUtils.info("request = {%s} \r\n result = {%s} \r\n", fullQueryUrl, result);
			} catch (Exception e) {
				result = "{'message':'error','data':'" + e.getMessage() + "'}";
			}
		}
		return result;
	}

	public void setSchemaRetrievalUrl(String schemaRetrievalUrl) {
		this.schemaRetrievalUrl = schemaRetrievalUrl;
	}

	public void setDataRetrievalUrl(String dataRetrievalUrl) {
		this.dataRetrievalUrl = dataRetrievalUrl;
	}

	/**
	 * get all ledgers count;
	 */
	@RequestMapping(method = RequestMethod.GET, path = "ledgers/count")
	@Override
	public int getLedgersCount() {
		return peerService.getQueryService().getLedgerHashs().length;
	}

	// 注： 账本的数量不会很多，不需要分页；
//	/**
//	 * get all ledgers hashs;
//	 */
//	@RequestMapping(method = RequestMethod.GET, path = "ledgers")
//	public HashDigest[] getLedgersHash(
//			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
//			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
//		return gatewayQueryService.getLedgersHash(fromIndex, count);
//	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/participants/count")
	public int getConsensusParticipantCount(@PathVariable(name = "ledgerHash") HashDigest ledgerHash) {
		return peerService.getQueryService(ledgerHash).getConsensusParticipants(ledgerHash).length;
	}

//	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/participants")
//	public ParticipantNode[] getConsensusParticipants(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
//			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
//			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
//
//		ParticipantNode participantNode[] = peerService.getQueryService().getConsensusParticipants(ledgerHash);
//		int indexAndCount[] = QueryUtil.calFromIndexAndCount(fromIndex, count, participantNode.length);
//		ParticipantNode participantNodesNew[] = Arrays.copyOfRange(participantNode, indexAndCount[0],
//				indexAndCount[0] + indexAndCount[1]);
//		return participantNodesNew;
//	}

	/**
	 * get more users by fromIndex and count;
	 *
	 * @param ledgerHash
	 * @param fromIndex
	 * @param count
	 * @return
	 */
	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/users")
	@Override
	public BlockchainIdentity[] getUsers(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return revertAccountHeader(peerService.getQueryService(ledgerHash).getUsers(ledgerHash, fromIndex, count));
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/accounts")
	@Override
	public BlockchainIdentity[] getDataAccounts(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return revertAccountHeader(peerService.getQueryService(ledgerHash).getDataAccounts(ledgerHash, fromIndex, count));
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/contracts")
	@Override
	public BlockchainIdentity[] getContractAccounts(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
			@RequestParam(name = "fromIndex", required = false, defaultValue = "0") int fromIndex,
			@RequestParam(name = "count", required = false, defaultValue = "-1") int count) {
		return revertAccountHeader(peerService.getQueryService(ledgerHash).getContractAccounts(ledgerHash, fromIndex, count));
	}

	/**
	 * reverse the BlockchainIdentity[] content; the latest record show first;
	 * @return
	 */
	private BlockchainIdentity[] revertAccountHeader(BlockchainIdentity[] accountHeaders){
		BlockchainIdentity[] accounts = new BlockchainIdentity[accountHeaders.length];
		if(accountHeaders!=null && accountHeaders.length>0){
			for (int i = 0; i < accountHeaders.length; i++) {
				accounts[accountHeaders.length-1-i] = accountHeaders[i];
			}
		}
		return accounts;
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/authorization/role/{roleName}")
	@Override
	public PrivilegeSet getRolePrivileges(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
										  @PathVariable(name = "roleName") String roleName) {

		return peerService.getQueryService(ledgerHash).getRolePrivileges(ledgerHash, roleName);
	}

	@RequestMapping(method = RequestMethod.GET, path = "ledgers/{ledgerHash}/authorization/user/{userAddress}")
	@Override
	public UserPrivilegeSet getUserPrivileges(@PathVariable(name = "ledgerHash") HashDigest ledgerHash,
											  @PathVariable(name = "userAddress") String userAddress) {
		return peerService.getQueryService(ledgerHash).getUserPrivileges(ledgerHash, userAddress);
	}
}
