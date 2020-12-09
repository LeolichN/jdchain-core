package com.jd.blockchain.consensus.bftsmart.client;

import com.jd.blockchain.consensus.ConsensusViewSettings;
import com.jd.blockchain.consensus.bftsmart.BftsmartClientIncomingSettings;
import com.jd.blockchain.crypto.PubKey;


public class BftsmartClientConfig implements BftsmartClientSettings {

    private int clientId;
    private PubKey clientPubkey;
    private ConsensusViewSettings consensusSettings;
    private byte[] topology;
    private byte[] tomConfig;
    BftsmartClientIncomingSettings clientIncomingSettings;

    public BftsmartClientConfig(int clientId, PubKey clientPubkey, ConsensusViewSettings consensusSettings, byte[] topology, byte[] tomConfig) {
        this.clientId = clientId;
        this.clientPubkey = clientPubkey;
        this.consensusSettings = consensusSettings;
        this.topology = topology;
        this.tomConfig = tomConfig;
    }

    public BftsmartClientConfig(BftsmartClientIncomingSettings clientIncomingSettings) {
        this.clientIncomingSettings = clientIncomingSettings;
        this.clientId = clientIncomingSettings.getClientId();
        this.clientPubkey = clientIncomingSettings.getPubKey();
        this.consensusSettings = clientIncomingSettings.getViewSettings();
        this.topology = clientIncomingSettings.getTopology();
        this.tomConfig = clientIncomingSettings.getTomConfig();

    }
    @Override
    public int getClientId() {
        return clientId;
    }

    public void setClientId(int clientId) {
        this.clientId = clientId;
    }


    @Override
    public PubKey getClientPubKey() {
        return clientPubkey;
    }

    public void setClientPubkey(PubKey clientPubkey) {
        this.clientPubkey = clientPubkey;
    }

    @Override
    public ConsensusViewSettings getConsensusSettings() {
        return consensusSettings;
    }

    public void setConsensusSettings(ConsensusViewSettings consensusSettings) {
        this.consensusSettings = consensusSettings;
    }

    public byte[] getTopology() {
        return topology;
    }

    public void setTopology(byte[] topology) {
        this.topology = topology;
    }

    @Override
    public byte[] getTomConfig() {
        return tomConfig;
    }

    public void setTomConfig(byte[] tomConfig) {
        this.tomConfig = tomConfig;
    }
}

