package com.jd.blockchain.ledger.core;

import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.crypto.PubKey;
import com.jd.blockchain.ledger.BlockchainIdentity;
import com.jd.blockchain.ledger.CryptoSetting;
import com.jd.blockchain.ledger.DigitalSignature;
import com.jd.blockchain.ledger.MerkleProof;
import com.jd.blockchain.storage.service.ExPolicyKVStorage;
import com.jd.blockchain.storage.service.VersioningKVStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.Bytes;
import utils.SkippingIterator;
import utils.Transactional;

public class DataAccountSetEditorSimple implements Transactional, DataAccountSet {
	private Logger logger = LoggerFactory.getLogger(DataAccountSetEditorSimple.class);

	private MerkleAccountSetEditor accountSet;

	public DataAccountSetEditorSimple(CryptoSetting cryptoSetting, String prefix, ExPolicyKVStorage exStorage,
                                      VersioningKVStorage verStorage, AccountAccessPolicy accessPolicy) {
		accountSet = new MerkleAccountSetEditor(cryptoSetting, Bytes.fromString(prefix), exStorage, verStorage, accessPolicy);
	}

	public DataAccountSetEditorSimple(HashDigest dataRootHash, CryptoSetting cryptoSetting, String prefix,
                                      ExPolicyKVStorage exStorage, VersioningKVStorage verStorage, boolean readonly,
                                      AccountAccessPolicy accessPolicy) {
		accountSet = new MerkleAccountSetEditor(dataRootHash, cryptoSetting, Bytes.fromString(prefix), exStorage, verStorage,
				readonly, accessPolicy);
	}

	@Override
	public SkippingIterator<BlockchainIdentity> identityIterator() {
		return accountSet.identityIterator();
	}

	public boolean isReadonly() {
		return accountSet.isReadonly();
	}

	@Override
	public HashDigest getRootHash() {
		return accountSet.getRootHash();
	}

	@Override
	public long getTotal() {
		return accountSet.getTotal();
	}

	@Override
	public boolean contains(Bytes address) {
		return accountSet.contains(address);
	}

	/**
	 * 返回账户的存在性证明；
	 */
	@Override
	public MerkleProof getProof(Bytes address) {
		return accountSet.getProof(address);
	}

	public DataAccount register(Bytes address, PubKey pubKey, DigitalSignature addressSignature) {
		// TODO: 未实现对地址签名的校验和记录；
		if(logger.isDebugEnabled()){
			logger.debug("before accountSet.register(),[address={}]",address.toBase58());
		}
		CompositeAccount accBase = accountSet.register(address, pubKey);
		if(logger.isDebugEnabled()){
			logger.debug("after accountSet.register(),[address={}]",address.toBase58());
		}
		return new DataAccount(accBase);
	}

	@Override
	public DataAccount getAccount(String address) {
		return getAccount(Bytes.fromBase58(address));
	}

	/**
	 * 返回数据账户； <br>
	 * 如果不存在，则返回 null；
	 *
	 * @param address
	 * @return
	 */
	@Override
	public DataAccount getAccount(Bytes address) {
		CompositeAccount accBase = accountSet.getAccount(address);
		if (accBase == null) {
			return null;
		}
		return new DataAccount(accBase);
	}

	@Override
	public DataAccount getAccount(Bytes address, long version) {
		CompositeAccount accBase = accountSet.getAccount(address, version);
		return new DataAccount(accBase);
	}

	@Override
	public boolean isUpdated() {
		return accountSet.isUpdated();
	}

	@Override
	public void commit() {
		accountSet.commit();
	}

	@Override
	public void cancel() {
		accountSet.cancel();
	}
}
