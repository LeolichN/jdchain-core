package com.jd.blockchain.ledger.core.handles;

import com.jd.blockchain.consensus.ConsensusProvider;
import com.jd.blockchain.consensus.ConsensusProviders;
import com.jd.blockchain.crypto.AddressEncoding;
import com.jd.blockchain.crypto.PubKey;
import com.jd.blockchain.ledger.*;
import com.jd.blockchain.ledger.core.*;
import com.jd.blockchain.transaction.UserRegisterOpTemplate;
import com.jd.blockchain.utils.Bytes;


public class ParticipantRegisterOperationHandle extends AbstractLedgerOperationHandle<ParticipantRegisterOperation> {
    public ParticipantRegisterOperationHandle() {
        super(ParticipantRegisterOperation.class);
    }

    @Override
    protected void doProcess(ParticipantRegisterOperation op, LedgerDataset newBlockDataset,
                             TransactionRequestExtension requestContext, LedgerQuery previousBlockDataset,
                             OperationHandleContext handleContext) {

        // 权限校验；
        SecurityPolicy securityPolicy = SecurityContext.getContextUsersPolicy();
        securityPolicy.checkEndpointPermission(LedgerPermission.REGISTER_PARTICIPANT, MultiIDsPolicy.AT_LEAST_ONE);

        ParticipantRegisterOperation participantRegOp = (ParticipantRegisterOperation) op;

        LedgerAdminDataset adminAccountDataSet = newBlockDataset.getAdminDataset();

        ConsensusProvider provider = ConsensusProviders.getProvider(adminAccountDataSet.getSettings().getConsensusProvider());

        ParticipantNode participantNode = new PartNode((int)(adminAccountDataSet.getParticipantCount()), op.getParticipantName(), op.getParticipantRegisterIdentity().getPubKey(), ParticipantNodeState.REGISTERED);

        //add new participant as consensus node
        adminAccountDataSet.addParticipant(participantNode);

        //update consensus nodes setting
        Bytes newConsensusSettings =  provider.getSettingsFactory().getConsensusSettingsBuilder().updateConsensusNodes(adminAccountDataSet.getSettings().getConsensusSetting(), op);

        LedgerSettings ledgerSetting = new LedgerConfiguration(adminAccountDataSet.getSettings().getConsensusProvider(),
                newConsensusSettings, adminAccountDataSet.getPreviousSetting().getCryptoSetting());

        adminAccountDataSet.setLedgerSetting(ledgerSetting);

        // Build UserRegisterOperation, reg participant as user
        UserRegisterOperation userRegOp = new UserRegisterOpTemplate(participantRegOp.getParticipantRegisterIdentity());
        handleContext.handle(userRegOp);
    }

    private static class PartNode implements ParticipantNode {

        private int id;

        private Bytes address;

        private String name;

        private PubKey pubKey;

        private ParticipantNodeState participantNodeState;

        public PartNode(int id, String name, PubKey pubKey, ParticipantNodeState participantNodeState) {
            this.id = id;
            this.name = name;
            this.pubKey = pubKey;
            this.address = AddressEncoding.generateAddress(pubKey);
            this.participantNodeState = participantNodeState;
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

        @Override
        public ParticipantNodeState getParticipantNodeState() {
            return participantNodeState;
        }
    }


}
