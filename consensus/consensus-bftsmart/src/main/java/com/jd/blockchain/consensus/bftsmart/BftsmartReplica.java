package com.jd.blockchain.consensus.bftsmart;

import com.jd.blockchain.consensus.Replica;
import com.jd.blockchain.crypto.PubKey;
import com.jd.blockchain.utils.Bytes;
import com.jd.blockchain.utils.net.NetworkAddress;

public class BftsmartReplica implements Replica{
	private int id;
	private Bytes address;
	private String name;
	private PubKey pubKey;
	private NetworkAddress networkAddress;

	public BftsmartReplica(int id, NetworkAddress networkAddress, Bytes address, PubKey pubKey) {
		this.id = id;
		this.networkAddress = networkAddress;
		this.address = address;
		this.pubKey = pubKey;
	}
	
	@Override
	public int getId() {
		return id;
	}

	@Override
	public Bytes getAddress() {
		return address;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public PubKey getPubKey() {
		return pubKey;
	}
	
	public NetworkAddress getNetworkAddress() {
		return networkAddress;
	}
}
