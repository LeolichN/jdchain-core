package com.jd.blockchain.ledger.core;

import com.jd.blockchain.ledger.*;

import java.util.List;

/**
 * 事务上下文；
 * 
 * @author huanghaiquan
 *
 */
public interface LedgerTransactionContext {

	/**
	 * 区块高度；
	 *
	 * @return
	 */
	long getBlockHeight();

	/**
	 * 账本数据集合；
	 * 
	 * @return
	 */
	LedgerDataSetEditor getDataset();

	/**
	 * 交易请求；
	 * 
	 * @return
	 */
	TransactionRequest getTransactionRequest();

	/**
	 * 提交对账本数据的修改，以指定的交易状态提交交易；
	 *
	 * @param txResult
	 *
	 * @return
	 */
	TransactionResult commit(TransactionState txResult);

	/**
	 * 提交对账本数据的修改，以指定的交易状态提交交易；
	 * 
	 * @param txResult
	 * @param operationResults
	 *
	 * @return
	 */
	TransactionResult commit(TransactionState txResult, List<OperationResult> operationResults);

	/**
	 * 抛弃对账本数据的修改，以指定的交易状态提交交易；<br>
	 *
	 * 通常来说，当在开启事务之后，修改账本或者尝试提交交易（{@link #commit(TransactionState)}）时发生错误，都应该抛弃数据，通过此方法记录一个表示错误状态的交易；
	 *
	 * @param txResult
	 * @return
	 */
	TransactionResult discardAndCommit(TransactionState txResult);

	/**
	 * 抛弃对账本数据的修改，以指定的交易状态提交交易；<br>
	 *
	 * 通常来说，当在开启事务之后，修改账本或者尝试提交交易（{@link #commit(TransactionState, List)}）时发生错误，都应该抛弃数据，通过此方法记录一个表示错误状态的交易；
	 *
	 * @param txResult
	 * @return
	 */
	TransactionResult discardAndCommit(TransactionState txResult, List<OperationResult> operationResults);

	/**
	 * 回滚事务，抛弃本次事务的所有数据更新；
	 */
	void rollback();

	/**
	 * 事件数据集合；
	 *
	 * @return
	 */
	LedgerEventSetEditor getEventSet();

	/**
	 * 交易数据集合；
	 *
	 * @return
	 */
	TransactionSet getTransactionSet();
}
