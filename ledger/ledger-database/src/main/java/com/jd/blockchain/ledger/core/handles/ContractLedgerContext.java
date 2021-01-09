package com.jd.blockchain.ledger.core.handles;

import java.util.ArrayList;
import java.util.List;

import com.jd.blockchain.contract.LedgerContext;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.ledger.BlockchainIdentity;
import com.jd.blockchain.ledger.BytesValue;
import com.jd.blockchain.ledger.ContractInfo;
import com.jd.blockchain.ledger.DataAccountInfo;
import com.jd.blockchain.ledger.DataAccountKVSetOperation;
import com.jd.blockchain.ledger.DataAccountRegisterOperation;
import com.jd.blockchain.ledger.Event;
import com.jd.blockchain.ledger.EventAccountRegisterOperation;
import com.jd.blockchain.ledger.EventPublishOperation;
import com.jd.blockchain.ledger.KVInfoVO;
import com.jd.blockchain.ledger.LedgerAdminInfo;
import com.jd.blockchain.ledger.LedgerBlock;
import com.jd.blockchain.ledger.LedgerInfo;
import com.jd.blockchain.ledger.LedgerMetadata;
import com.jd.blockchain.ledger.LedgerTransaction;
import com.jd.blockchain.ledger.Operation;
import com.jd.blockchain.ledger.ParticipantNode;
import com.jd.blockchain.ledger.PrivilegeSet;
import com.jd.blockchain.ledger.TransactionState;
import com.jd.blockchain.ledger.TypedKVEntry;
import com.jd.blockchain.ledger.TypedValue;
import com.jd.blockchain.ledger.UserInfo;
import com.jd.blockchain.ledger.UserPrivilegeSet;
import com.jd.blockchain.ledger.UserRegisterOperation;
import com.jd.blockchain.ledger.core.OperationHandleContext;
import com.jd.blockchain.transaction.BlockchainQueryService;
import com.jd.blockchain.transaction.DataAccountKVSetOperationBuilder;
import com.jd.blockchain.transaction.DataAccountRegisterOperationBuilder;
import com.jd.blockchain.transaction.DataAccountRegisterOperationBuilderImpl;
import com.jd.blockchain.transaction.EventAccountRegisterOperationBuilder;
import com.jd.blockchain.transaction.EventAccountRegisterOperationBuilderImpl;
import com.jd.blockchain.transaction.EventData;
import com.jd.blockchain.transaction.EventPublishOperationBuilder;
import com.jd.blockchain.transaction.KVData;
import com.jd.blockchain.transaction.UserRegisterOperationBuilder;
import com.jd.blockchain.transaction.UserRegisterOperationBuilderImpl;

import utils.Bytes;

public class ContractLedgerContext implements LedgerContext {

	private BlockchainQueryService innerQueryService;

	private OperationHandleContext opHandleContext;

	private List<Operation> generatedOpList = new ArrayList<>();

	public ContractLedgerContext(BlockchainQueryService innerQueryService, OperationHandleContext opHandleContext) {
		this.innerQueryService = innerQueryService;
		this.opHandleContext = opHandleContext;
	}

	@Override
	public HashDigest[] getLedgerHashs() {
		return innerQueryService.getLedgerHashs();
	}

	@Override
	public LedgerInfo getLedger(HashDigest ledgerHash) {
		return innerQueryService.getLedger(ledgerHash);
	}

	@Override
	public LedgerAdminInfo getLedgerAdminInfo(HashDigest ledgerHash) {
		return innerQueryService.getLedgerAdminInfo(ledgerHash);
	}

	@Override
	public ParticipantNode[] getConsensusParticipants(HashDigest ledgerHash) {
		return innerQueryService.getConsensusParticipants(ledgerHash);
	}

	@Override
	public LedgerMetadata getLedgerMetadata(HashDigest ledgerHash) {
		return innerQueryService.getLedgerMetadata(ledgerHash);
	}

	@Override
	public LedgerBlock getBlock(HashDigest ledgerHash, long height) {
		return innerQueryService.getBlock(ledgerHash, height);
	}

	@Override
	public LedgerBlock getBlock(HashDigest ledgerHash, HashDigest blockHash) {
		return innerQueryService.getBlock(ledgerHash, blockHash);
	}

	@Override
	public long getTransactionCount(HashDigest ledgerHash, long height) {
		return innerQueryService.getTransactionCount(ledgerHash, height);
	}

	@Override
	public long getTransactionCount(HashDigest ledgerHash, HashDigest blockHash) {
		return innerQueryService.getTransactionCount(ledgerHash, blockHash);
	}

	@Override
	public long getTransactionTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getTransactionTotalCount(ledgerHash);
	}

	@Override
	public long getDataAccountCount(HashDigest ledgerHash, long height) {
		return innerQueryService.getDataAccountCount(ledgerHash, height);
	}

	@Override
	public long getDataAccountCount(HashDigest ledgerHash, HashDigest blockHash) {
		return innerQueryService.getDataAccountCount(ledgerHash, blockHash);
	}

	@Override
	public long getDataAccountTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getDataAccountTotalCount(ledgerHash);
	}

	@Override
	public long getUserCount(HashDigest ledgerHash, long height) {
		return innerQueryService.getUserCount(ledgerHash, height);
	}

	@Override
	public long getUserCount(HashDigest ledgerHash, HashDigest blockHash) {
		return innerQueryService.getUserCount(ledgerHash, blockHash);
	}

	@Override
	public long getUserTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getUserTotalCount(ledgerHash);
	}

	@Override
	public long getContractCount(HashDigest ledgerHash, long height) {
		return innerQueryService.getContractCount(ledgerHash, height);
	}

	@Override
	public long getContractCount(HashDigest ledgerHash, HashDigest blockHash) {
		return innerQueryService.getContractCount(ledgerHash, blockHash);
	}

	@Override
	public long getContractTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getContractTotalCount(ledgerHash);
	}

	@Override
	public LedgerTransaction[] getTransactions(HashDigest ledgerHash, long height, int fromIndex, int count) {
		return innerQueryService.getTransactions(ledgerHash, height, fromIndex, count);
	}

	@Override
	public LedgerTransaction[] getTransactions(HashDigest ledgerHash, HashDigest blockHash, int fromIndex, int count) {
		return innerQueryService.getTransactions(ledgerHash, blockHash, fromIndex, count);
	}

	@Override
	public LedgerTransaction[] getAdditionalTransactions(HashDigest ledgerHash, long height, int fromIndex, int count) {
		return innerQueryService.getAdditionalTransactions(ledgerHash, height, fromIndex, count);
	}

	@Override
	public LedgerTransaction[] getAdditionalTransactions(HashDigest ledgerHash, HashDigest blockHash, int fromIndex, int count) {
		return innerQueryService.getAdditionalTransactions(ledgerHash, blockHash, fromIndex, count);
	}

	@Override
	public LedgerTransaction getTransactionByContentHash(HashDigest ledgerHash, HashDigest contentHash) {
		return innerQueryService.getTransactionByContentHash(ledgerHash, contentHash);
	}

	@Override
	public TransactionState getTransactionStateByContentHash(HashDigest ledgerHash, HashDigest contentHash) {
		return innerQueryService.getTransactionStateByContentHash(ledgerHash, contentHash);
	}

	@Override
	public UserInfo getUser(HashDigest ledgerHash, String address) {
		return innerQueryService.getUser(ledgerHash, address);
	}

	@Override
	public DataAccountInfo getDataAccount(HashDigest ledgerHash, String address) {
		return innerQueryService.getDataAccount(ledgerHash, address);
	}

	@Override
	public TypedKVEntry[] getDataEntries(HashDigest ledgerHash, String address, String... keys) {
		return innerQueryService.getDataEntries(ledgerHash, address, keys);
	}

	@Override
	public TypedKVEntry[] getDataEntries(HashDigest ledgerHash, String address, KVInfoVO kvInfoVO) {
		return innerQueryService.getDataEntries(ledgerHash, address, kvInfoVO);
	}

	@Override
	public TypedKVEntry[] getDataEntries(HashDigest ledgerHash, String address, int fromIndex, int count) {
		return innerQueryService.getDataEntries(ledgerHash, address, fromIndex, count);
	}

	@Override
	public long getDataEntriesTotalCount(HashDigest ledgerHash, String address) {
		return innerQueryService.getDataEntriesTotalCount(ledgerHash, address);
	}

	@Override
	public ContractInfo getContract(HashDigest ledgerHash, String address) {
		return innerQueryService.getContract(ledgerHash, address);
	}

	@Override
	public Event[] getSystemEvents(HashDigest ledgerHash, String eventName, long fromSequence, int maxCount) {
		return innerQueryService.getSystemEvents(ledgerHash, eventName, fromSequence, maxCount);
	}

	@Override
	public long getSystemEventNameTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getSystemEventNameTotalCount(ledgerHash);
	}

	@Override
	public String[] getSystemEventNames(HashDigest ledgerHash, int fromIndex, int count) {
		return innerQueryService.getSystemEventNames(ledgerHash, fromIndex, count);
	}

	@Override
	public Event getLatestEvent(HashDigest ledgerHash, String eventName) {
		return innerQueryService.getLatestEvent(ledgerHash, eventName);
	}

	@Override
	public long getSystemEventsTotalCount(HashDigest ledgerHash, String eventName) {
		return innerQueryService.getSystemEventsTotalCount(ledgerHash, eventName);
	}

	@Override
	public BlockchainIdentity[] getUserEventAccounts(HashDigest ledgerHash, int fromIndex, int count) {
		return innerQueryService.getUserEventAccounts(ledgerHash, fromIndex, count);
	}

	@Override
	public BlockchainIdentity getUserEventAccount(HashDigest ledgerHash, String address) {
		return innerQueryService.getUserEventAccount(ledgerHash, address);
	}

	@Override
	public long getUserEventAccountTotalCount(HashDigest ledgerHash) {
		return innerQueryService.getUserEventAccountTotalCount(ledgerHash);
	}

	@Override
	public long getUserEventNameTotalCount(HashDigest ledgerHash, String address) {
		return innerQueryService.getUserEventNameTotalCount(ledgerHash, address);
	}

	@Override
	public String[] getUserEventNames(HashDigest ledgerHash, String address, int fromSequence, int count) {
		return innerQueryService.getUserEventNames(ledgerHash, address, fromSequence, count);
	}

	@Override
	public Event getLatestEvent(HashDigest ledgerHash, String address, String eventName) {
		return innerQueryService.getLatestEvent(ledgerHash, address, eventName);
	}

	@Override
	public long getUserEventsTotalCount(HashDigest ledgerHash, String address, String eventName) {
		return innerQueryService.getUserEventsTotalCount(ledgerHash, address, eventName);
	}

	@Override
	public Event[] getUserEvents(HashDigest ledgerHash, String address, String eventName, long fromSequence, int count) {
		return innerQueryService.getUserEvents(ledgerHash, address, eventName, fromSequence, count);
	}

	@Override
	public ContractInfo getContract(HashDigest ledgerHash, String address, long version) {
		return innerQueryService.getContract(ledgerHash, address, version);
	}

	// ---------------------------user()----------------------------

	@Override
	public BlockchainIdentity[] getUsers(HashDigest ledgerHash, int fromIndex, int count) {
		return innerQueryService.getUsers(ledgerHash, fromIndex, count);
	}

	@Override
	public BlockchainIdentity[] getDataAccounts(HashDigest ledgerHash, int fromIndex, int count) {
		return innerQueryService.getDataAccounts(ledgerHash, fromIndex, count);
	}

	@Override
	public BlockchainIdentity[] getContractAccounts(HashDigest ledgerHash, int fromIndex, int count) {
		return innerQueryService.getContractAccounts(ledgerHash, fromIndex, count);
	}

	@Override
	public UserRegisterOperationBuilder users() {
		return new UserRegisterOperationBuilder1();
	}

	@Override
	public DataAccountRegisterOperationBuilder dataAccounts() {
		return new DataAccountRegisterOperationBuilder1();
	}

	@Override
	public DataAccountKVSetOperationBuilder dataAccount(String accountAddress) {
		return new DataAccountKVSetOperationExecBuilder(Bytes.fromBase58(accountAddress));
	}

	@Override
	public DataAccountKVSetOperationBuilder dataAccount(Bytes accountAddress) {
		return new DataAccountKVSetOperationExecBuilder(accountAddress);
	}

	@Override
	public EventAccountRegisterOperationBuilder eventAccounts() {
		return new EventAccountRegisterOperationBuilder1();
	}

	@Override
	public EventPublishOperationBuilder eventAccount(String accountAddress) {
		return new EventPublishOperationExecBuilder(Bytes.fromBase58(accountAddress));
	}

	@Override
	public EventPublishOperationBuilder eventAccount(Bytes accountAddress) {
		return new EventPublishOperationExecBuilder(accountAddress);
	}

	@Override
	public PrivilegeSet getRolePrivileges(HashDigest ledgerHash, String roleName) {
		return innerQueryService.getRolePrivileges(ledgerHash, roleName);
	}

	@Override
	public UserPrivilegeSet getUserPrivileges(HashDigest ledgerHash, String userAddress) {
		return innerQueryService.getUserPrivileges(ledgerHash, userAddress);
	}

	// ========end=============

	private class DataAccountRegisterOperationBuilder1 implements DataAccountRegisterOperationBuilder {
		@Override
		public DataAccountRegisterOperation register(BlockchainIdentity accountID) {
			final DataAccountRegisterOperationBuilderImpl DATA_ACC_REG_OP_BUILDER = new DataAccountRegisterOperationBuilderImpl();
			DataAccountRegisterOperation op = DATA_ACC_REG_OP_BUILDER.register(accountID);
			generatedOpList.add(op);
			opHandleContext.handle(op);
			return op;
		}
	}

	private class UserRegisterOperationBuilder1 implements UserRegisterOperationBuilder {
		private final UserRegisterOperationBuilderImpl USER_REG_OP_BUILDER = new UserRegisterOperationBuilderImpl();

		@Override
		public UserRegisterOperation register(BlockchainIdentity userID) {
			UserRegisterOperation op = USER_REG_OP_BUILDER.register(userID);
			generatedOpList.add(op);
			opHandleContext.handle(op);
			return op;
		}
	}

	private class EventAccountRegisterOperationBuilder1 implements EventAccountRegisterOperationBuilder {
		@Override
		public EventAccountRegisterOperation register(BlockchainIdentity accountID) {
			final EventAccountRegisterOperationBuilderImpl EVENT_ACC_REG_OP_BUILDER = new EventAccountRegisterOperationBuilderImpl();
			EventAccountRegisterOperation op = EVENT_ACC_REG_OP_BUILDER.register(accountID);
			generatedOpList.add(op);
			opHandleContext.handle(op);
			return op;
		}
	}

	// --------------------------------

	private class DataAccountKVSetOperationExecBuilder implements DataAccountKVSetOperationBuilder {

		private Bytes accountAddress;

		private SingleKVSetOpTemplate op;

		public DataAccountKVSetOperationExecBuilder(Bytes accountAddress) {
			this.accountAddress = accountAddress;
		}

		@Override
		public DataAccountKVSetOperation getOperation() {
			return op;
		}

//		@Override
//		public DataAccountKVSetOperationBuilder set(String key, byte[] value, long expVersion) {
//			BytesValue bytesValue = BytesValueEntry.fromBytes(value);
//			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
//			handle(op);
//			return this;
//		}

		@Override
		public DataAccountKVSetOperationBuilder setText(String key, String value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromText(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setBytes(String key, Bytes value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromBytes(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setInt64(String key, long value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromInt64(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

//		@Deprecated
//		@Override
//		public DataAccountKVSetOperationBuilder set(String key, String value, long expVersion) {
//			BytesValue bytesValue = BytesValueEntry.fromText(value);
//			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
//			handle(op);
//			return this;
//		}

		@Override
		public DataAccountKVSetOperationBuilder setJSON(String key, String value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromJSON(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setXML(String key, String value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromXML(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setBytes(String key, byte[] value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromBytes(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setImage(String key, byte[] value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromImage(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		@Override
		public DataAccountKVSetOperationBuilder setTimestamp(String key, long value, long expVersion) {
			BytesValue bytesValue = TypedValue.fromTimestamp(value);
			this.op = new SingleKVSetOpTemplate(key, bytesValue, expVersion);
			handle(op);
			return this;
		}

		private void handle(Operation op) {
			generatedOpList.add(op);
			opHandleContext.handle(op);
		}

		/**
		 * 单个KV写入操作；
		 *
		 * @author huanghaiquan
		 *
		 */
		private class SingleKVSetOpTemplate implements DataAccountKVSetOperation {

			private KVWriteEntry[] writeset = new KVWriteEntry[1];

			private SingleKVSetOpTemplate(String key, BytesValue value, long expVersion) {
				writeset[0] = new KVData(key, value, expVersion);
			}

			@Override
			public Bytes getAccountAddress() {
				return accountAddress;
			}

			@Override
			public KVWriteEntry[] getWriteSet() {
				return writeset;
			}

		}
	}

	private class EventPublishOperationExecBuilder implements EventPublishOperationBuilder {

		private Bytes eventAddress;

		private SingleEventPublishOpTemplate op;

		public EventPublishOperationExecBuilder(Bytes eventAddress) {
			this.eventAddress = eventAddress;
		}

		private void handle(Operation op) {
			generatedOpList.add(op);
			opHandleContext.handle(op);
		}

		@Override
		public EventPublishOperation getOperation() {
			return op;
		}

		@Override
		public EventPublishOperationBuilder publish(String name, byte[] content, long sequence) {
			BytesValue bytesValue = TypedValue.fromBytes(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publish(String name, Bytes content, long sequence) {
			BytesValue bytesValue = TypedValue.fromBytes(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publish(String name, String content, long sequence) {
			BytesValue bytesValue = TypedValue.fromText(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publish(String name, long content, long sequence) {
			BytesValue bytesValue = TypedValue.fromInt64(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publishTimestamp(String name, long content, long sequence) {
			BytesValue bytesValue = TypedValue.fromTimestamp(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publishImage(String name, byte[] content, long sequence) {
			BytesValue bytesValue = TypedValue.fromImage(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publishJSON(String name, String content, long sequence) {
			BytesValue bytesValue = TypedValue.fromJSON(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		@Override
		public EventPublishOperationBuilder publishXML(String name, String content, long sequence) {
			BytesValue bytesValue = TypedValue.fromXML(content);
			this.op = new EventPublishOperationExecBuilder.SingleEventPublishOpTemplate(name, bytesValue, sequence);
			handle(op);
			return this;
		}

		/**
		 * 单个事件发布操作
		 */
		private class SingleEventPublishOpTemplate implements EventPublishOperation {

			private EventEntry[] writeset = new EventEntry[1];

			private SingleEventPublishOpTemplate(String key, BytesValue value, long expVersion) {
				writeset[0] = new EventData(key, value, expVersion);
			}

			@Override
			public Bytes getEventAddress() {
				return eventAddress;
			}

			@Override
			public EventEntry[] getEvents() {
				return writeset;
			}
		}
	}
}
