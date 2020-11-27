package com.jd.blockchain.consensus.bftsmart.client;

import bftsmart.reconfiguration.util.TOMConfiguration;
import bftsmart.reconfiguration.views.MemoryBasedViewStorage;
import bftsmart.reconfiguration.views.NodeNetwork;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.AsynchServiceProxy;
import com.jd.blockchain.consensus.bftsmart.BftsmartTopology;
import com.jd.blockchain.utils.serialize.binary.BinarySerializeUtils;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

public class BftsmartPeerProxyFactory extends BasePooledObjectFactory<AsynchServiceProxy> {
    private static Logger LOGGER = LoggerFactory.getLogger(BftsmartPeerProxyFactory.class);
    private BftsmartClientSettings bftsmartClientSettings;

    private int gatewayId;

    private AtomicInteger index = new AtomicInteger(1);

    public BftsmartPeerProxyFactory(BftsmartClientSettings bftsmartClientSettings, int gatewayId) {
        this.bftsmartClientSettings = bftsmartClientSettings;
        this.gatewayId = gatewayId;
    }

    @Override
    public AsynchServiceProxy create() throws Exception {

        BftsmartTopology topology = BinarySerializeUtils.deserialize(bftsmartClientSettings.getTopology());

        View view = topology.getView();
        if (view != null) {
            // 打印view
            int[] processes = view.getProcesses();
            for (int process : processes) {
                NodeNetwork address = view.getAddress(process);
//                if(LOGGER.isDebugEnabled()){
                    LOGGER.info("read topology id = {}, address = {} \r\n",
                            process, address);
//                }
            }
        }

        MemoryBasedViewStorage viewStorage = new MemoryBasedViewStorage(topology.getView());
        TOMConfiguration tomConfiguration = BinarySerializeUtils.deserialize(bftsmartClientSettings.getTomConfig());

        //every proxy client has unique id;
        tomConfiguration.setProcessId(gatewayId + index.getAndIncrement());
        AsynchServiceProxy peerProxy = new AsynchServiceProxy(tomConfiguration, viewStorage);
        return peerProxy;
    }

    @Override
    public PooledObject<AsynchServiceProxy> wrap(AsynchServiceProxy asynchServiceProxy) {
        return new DefaultPooledObject<>(asynchServiceProxy);
    }
}
