package org.zaproxy.zap.extension.tokengen;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

public class TokenGeneratorInstance {

    private List<TokenGenerator> generators = Collections.emptyList();
    private int runningGenerators = 0;
    private CharacterFrequencyMap cfm = null;
    private boolean manuallyStopped = false;
    private TokenPanel tokenPanel;
    private AnalyseTokensDialog analyseTokensDialog = null;

    ExtensionTokenGen extensionTokenGen;

    private static final Logger LOGGER = LogManager.getLogger(TokenGeneratorInstance.class);

    public TokenGeneratorInstance(ExtensionTokenGen extensionTokenGen) {
        this.extensionTokenGen = extensionTokenGen;
        this.tokenPanel = new TokenPanel(extensionTokenGen, this);
    }

    public TokenGeneratorInstance(ExtensionTokenGen extensionTokenGen, TokenPanel tokenPanel) {
        this.extensionTokenGen = extensionTokenGen;
        this.tokenPanel = tokenPanel;
    }


    @SuppressWarnings("fallthrough")
    public void startTokenGeneration(HttpMessage msg, int numGen, HtmlParameterStats htmlParameterStats,
                                     boolean shouldRemoveCookie) {
        switch (Control.getSingleton().getMode()) {
            case safe:
                throw new IllegalStateException("Token generation is not allowed in Safe mode");
            case protect:
                if (!msg.isInScope()) {
                    throw new IllegalStateException(
                            "Token generation is not allowed with a message not in scope when in Protected mode: "
                                    + msg.getRequestHeader().getURI());
                }
            case standard:
            case attack:
                // No problem
                break;
        }

        this.cfm = new CharacterFrequencyMap();
        LOGGER.debug("startTokenGeneration {} # {}", msg.getRequestHeader().getURI(), numGen);
        this.getTokenPanel().scanStarted(numGen);

        int numThreads = extensionTokenGen.getTokenParam().getThreadsPerScan();
        this.manuallyStopped = false;

        generators = new ArrayList<>();

        for (int i = 0; i < numThreads; i++) {
            TokenGenerator gen = new TokenGenerator();
            generators.add(gen);

            gen.setTokenGeneratorInstance(this);
            gen.setHttpMessage(msg);
            gen.setNumberTokens(numGen / numThreads); // TODO what about remainder?
            gen.setTargetToken(htmlParameterStats);
            gen.setRequestDelay(extensionTokenGen.getTokenParam().getRequestDelayInMs(), TimeUnit.MILLISECONDS);
            gen.setShouldRemoveCookie(shouldRemoveCookie);
            gen.execute();
            this.runningGenerators++;
        }
    }

    protected void addTokenResult(HttpMessage msg, HtmlParameterStats targetToken) {
        // Extract the token
        String token = null;
        switch (targetToken.getType()) {
            case cookie:
                TreeSet<HtmlParameter> cookies = msg.getCookieParams();
                Iterator<HtmlParameter> iter = cookies.iterator();
                while (iter.hasNext()) {
                    HtmlParameter cookie = iter.next();
                    if (cookie.getName().equals(targetToken.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
                break;
            case form:
                token = extensionTokenGen.getTokenValue(msg, targetToken.getName());
                break;
            case url:
                // TODO
                break;
        }
        if (token != null) {
            this.cfm.addToken(token);
            msg.setNote(token);
        }

        this.getTokenPanel().addTokenResult(new MessageSummary(msg));
    }
    protected void generatorStopped() {
        this.runningGenerators--;
        LOGGER.debug("generatorStopped runningGenerators {}", runningGenerators);

        if (this.runningGenerators <= 0) {
            LOGGER.debug("generatorStopped scanFinished");
            this.getTokenPanel().scanFinshed();

            if (!manuallyStopped) {
                showAnalyseTokensDialog();
            }
        }
    }

    public void showAnalyseTokensDialog() {
        this.getAnalyseTokensDialog().reset();
        this.getAnalyseTokensDialog().setVisible(true);
        this.getAnalyseTokensDialog().startAnalysis(this.cfm);
        this.extensionTokenGen.getScanStatus().decScanCount();
    }

    public AnalyseTokensDialog getAnalyseTokensDialog() {
        if (this.analyseTokensDialog == null) {
            this.analyseTokensDialog = new AnalyseTokensDialog(this.extensionTokenGen.getMessages());
            this.analyseTokensDialog.setExtension(this.extensionTokenGen);
        }
        return this.analyseTokensDialog;
    }

    public void stopTokenGeneration() {
        this.manuallyStopped = true;
        for (TokenGenerator gen : generators) {
            gen.stopGenerating();
        }
    }

    public void pauseTokenGeneration() {
        for (TokenGenerator gen : generators) {
            gen.setPaused(true);
        }
    }

    public void resumeTokenGeneration() {
        for (TokenGenerator gen : generators) {
            gen.setPaused(false);
        }
    }

    public int getRunningGenerators() {
        return runningGenerators;
    }

    public void resetGenerators() {
        this.generators = Collections.emptyList();
    }

    public void resetTokenPanel() {
        this.tokenPanel.reset();
    }

    public TokenPanel getTokenPanel() {
        return tokenPanel;
    }

    public void setCfm(CharacterFrequencyMap cfm) {
        this.cfm = cfm;
    }
}
