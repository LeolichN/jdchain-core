package com.jd.blockchain.ledger.core.handles;

import com.jd.blockchain.ledger.*;
import com.jd.blockchain.ledger.DataAccountKVSetOperation.KVWriteEntry;
import com.jd.blockchain.ledger.core.DataAccount;
import com.jd.blockchain.ledger.core.LedgerQuery;
import com.jd.blockchain.ledger.core.LedgerTransactionContext;
import com.jd.blockchain.ledger.core.OperationHandleContext;
import com.jd.blockchain.ledger.core.TransactionRequestExtension;
import com.jd.blockchain.ledger.core.EventManager;
import com.jd.blockchain.transaction.DataAccountChameleonOnceCheck;
import utils.Bytes;
import utils.io.BytesUtils;

public class DataAccountKVSetOperationHandle extends AbstractLedgerOperationHandle<DataAccountKVSetOperation> {

	private static final String DATA_ACCOUNT_HASH_ONCE_KEY = "DATA_ACCOUNT_HASH_ONCE_KEY";

	public DataAccountKVSetOperationHandle() {
		super(DataAccountKVSetOperation.class);
	}

	@Override
	protected void doProcess(DataAccountKVSetOperation kvWriteOp, LedgerTransactionContext transactionContext,
			TransactionRequestExtension requestContext, LedgerQuery ledger, 
			OperationHandleContext handleContext, EventManager manager) {
		// 权限校验；
		SecurityPolicy securityPolicy = SecurityContext.getContextUsersPolicy();
		securityPolicy.checkEndpointPermission(LedgerPermission.WRITE_DATA_ACCOUNT, MultiIDsPolicy.AT_LEAST_ONE);

		// 操作账本；
		DataAccount account = transactionContext.getDataset().getDataAccountSet().getAccount(kvWriteOp.getAccountAddress());
		if (account == null) {
			throw new DataAccountDoesNotExistException(String.format("Data account doesn't exist! --[Address=%s]", kvWriteOp.getAccountAddress()));
		}

		// 写权限校验
		securityPolicy.checkDataPermission(account.getPermission(), DataPermissionType.WRITE);

		KVWriteEntry[] writeSet = kvWriteOp.getWriteSet();
		long v = -1L;
		byte[] onceHashData = null;

		for (KVWriteEntry kvw : writeSet) {
			v = account.getDataset().setValue(kvw.getKey(), TypedValue.wrap(kvw.getValue()), kvw.getExpectedVersion());
			if (v < 0) {
				throw new DataVersionConflictException();
			}
			if(kvw.chameleonHash()){
				if(onceHashData == null){
					onceHashData = kvw.getValue().getBytes().toBytes();
				}else{
					onceHashData = BytesUtils.concat(onceHashData,kvw.getValue().getBytes().toBytes());
				}
			}
		}
		if(onceHashData != null){
			DataAccountChameleonOnceCheck chameleonOnceCheck = new ChameleonOnceCheck();
			byte[] hashResult = chameleonOnceCheck.hashDataOnce(onceHashData,account.getPubKey().getRawKeyBytes());
			if(account.getDataset().getValue(account.getAddress().toBase58()) != null){
				throw new DataVersionConflictException();
			}else{
				account.getDataset().setValue(account.getAddress().toBase58(),TypedValue.fromBoolean(true));
			}
		}
	}

}
