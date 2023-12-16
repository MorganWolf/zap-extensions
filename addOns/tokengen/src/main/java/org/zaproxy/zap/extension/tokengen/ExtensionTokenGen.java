/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.tokengen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.Vector;
import javax.swing.ImageIcon;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.ScanStatus;

/*
 * Entry point to the ExtensionTokenGen.
 *
 */
public class ExtensionTokenGen extends ExtensionAdaptor {

    public static final String NAME = "ExtensionTokenGen";

    private TokenGenPopupMenu popupTokenGenMenu = null;
    private GenerateTokensDialog genTokensDialog = null;

    private TokenParam tokenParam = null;
    private TokenOptionsPanel tokenOptionsPanel;
    private ScanStatus scanStatus;

    UUID defaultInstanceUuid = UUID.randomUUID();
    Map<UUID, TokenGeneratorInstance> mapOfTokenGeneratorInstance = new HashMap<>();

    /** */
    public ExtensionTokenGen() {
        super(NAME);
        this.setI18nPrefix("tokengen");
    }

    @Override
    public void init() {
        super.init();

        TokenAnalysisTestResult.setResourceBundle(getMessages());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addSessionListener(new SessionChangedListenerImpl());
        extensionHook.addApiImplementor(new TokenGenApi(this));

        extensionHook.addOptionsParamSet(getTokenParam());

        if (hasView()) {
            // Register our popup menu item, as long as we're not running as a daemon
            extensionHook.getHookMenu().addPopupMenuItem(getPopupTokenGen());
            TokenGeneratorInstance defaultInstance = new TokenGeneratorInstance(this);
            extensionHook.getHookView().addStatusPanel(defaultInstance.getTokenPanel());
            defaultInstance
                    .getTokenPanel()
                    .setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
            mapOfTokenGeneratorInstance.put(defaultInstanceUuid, defaultInstance);
            extensionHook.getHookView().addOptionPanel(getTokenOptionsPanel());

            this.scanStatus =
                    new ScanStatus(
                            new ImageIcon(
                                    getClass().getResource("/resource/icon/fugue/barcode.png")),
                            this.getMessages().getString("tokengen.panel.title"));
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }
    }

    public UUID createTokenGeneratorInstance() {
        TokenGeneratorInstance defaultInstance =
                mapOfTokenGeneratorInstance.get(defaultInstanceUuid);
        TokenGeneratorInstance instance =
                new TokenGeneratorInstance(this, defaultInstance.getTokenPanel());
        UUID uniqueId = UUID.randomUUID();
        mapOfTokenGeneratorInstance.put(uniqueId, instance);
        scanStatus.incScanCount();
        return uniqueId;
    }

    public Map<UUID, TokenGeneratorInstance> getMapOfTokenGeneratorInstance() {
        return mapOfTokenGeneratorInstance;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        mapOfTokenGeneratorInstance.values().forEach(TokenGeneratorInstance::stopTokenGeneration);

        if (hasView()) {
            mapOfTokenGeneratorInstance.values().stream()
                    .map(TokenGeneratorInstance::getAnalyseTokensDialog)
                    .filter(Objects::nonNull)
                    .forEach(AnalyseTokensDialog::dispose);

            if (genTokensDialog != null) {
                genTokensDialog.dispose();
            }

            mapOfTokenGeneratorInstance
                    .values()
                    .forEach(
                            instance ->
                                    getView()
                                            .getMainFrame()
                                            .getMainFooterPanel()
                                            .removeFooterToolbarRightLabel(
                                                    scanStatus.getCountLabel()));
            scanStatus.setScanCount(0);
        }

        super.unload();
    }

    @Override
    public List<String> getActiveActions() {

        if (mapOfTokenGeneratorInstance.values().stream()
                .allMatch(instance -> instance.getRunningGenerators() == 0)) {
            return null;
        }

        List<String> activeActions = new ArrayList<>(1);
        activeActions.add(Constant.messages.getString("tokengen.activeAction"));
        return activeActions;
    }

    public TokenParam getTokenParam() {
        if (tokenParam == null) {
            tokenParam = new TokenParam();
        }
        return tokenParam;
    }

    private TokenOptionsPanel getTokenOptionsPanel() {
        if (tokenOptionsPanel == null) {
            tokenOptionsPanel = new TokenOptionsPanel();
        }
        return tokenOptionsPanel;
    }

    // TODO This method is also in ExtensionAntiCSRF - put into a helper class?
    public String getTokenValue(HttpMessage tokenMsg, String tokenName) {
        Source source = new Source(tokenMsg.getResponseBody().toString());
        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags

            for (Element formElement : formElements) {
                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);

                if (inputElements != null && inputElements.size() > 0) {
                    // Loop through all of the INPUT elements
                    for (Element inputElement : inputElements) {
                        String id = inputElement.getAttributeValue("ID");
                        if (id != null && id.equalsIgnoreCase(tokenName)) {
                            return inputElement.getAttributeValue("VALUE");
                        }
                        String name = inputElement.getAttributeValue("NAME");
                        if (name != null && name.equalsIgnoreCase(tokenName)) {
                            return inputElement.getAttributeValue("VALUE");
                        }
                    }
                }
            }
        }
        return null;
    }

    public Vector<String> getFormInputFields(HttpMessage tokenMsg) {
        Source source = new Source(tokenMsg.getResponseBody().toString());
        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
        Vector<String> fifs = new Vector<>();

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags

            for (Element formElement : formElements) {
                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);

                if (inputElements != null && inputElements.size() > 0) {
                    // Loop through all of the INPUT elements
                    for (Element inputElement : inputElements) {
                        String id = inputElement.getAttributeValue("ID");
                        if (id != null && id.length() > 0) {
                            fifs.add(id);
                        } else {
                            String name = inputElement.getAttributeValue("NAME");
                            if (name != null && name.length() > 0) {
                                fifs.add(name);
                            }
                        }
                    }
                }
            }
        }
        return fifs;
    }

    private TokenGenPopupMenu getPopupTokenGen() {
        if (popupTokenGenMenu == null) {
            popupTokenGenMenu =
                    new TokenGenPopupMenu(
                            getMessages().getString("tokengen.generate.popup.generate"));
            popupTokenGenMenu.setExtension(this);
        }
        return popupTokenGenMenu;
    }

    private GenerateTokensDialog getGenerateTokensDialog() {
        if (this.genTokensDialog == null) {
            this.genTokensDialog = new GenerateTokensDialog(getMessages());
            this.genTokensDialog.setExtension(this);
        }
        return this.genTokensDialog;
    }

    public void showGenerateTokensDialog(HttpMessage msg) {
        this.getGenerateTokensDialog().setMessage(msg);
        this.getGenerateTokensDialog().setVisible(true);
    }

    public ScanStatus getScanStatus() {
        return scanStatus;
    }

    @Override
    public String getDescription() {
        return getMessages().getString("tokengen.desc");
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            mapOfTokenGeneratorInstance
                    .values()
                    .forEach(TokenGeneratorInstance::stopTokenGeneration);
            mapOfTokenGeneratorInstance.values().forEach(TokenGeneratorInstance::resetGenerators);
            mapOfTokenGeneratorInstance.values().forEach(TokenGeneratorInstance::resetTokenPanel);
            mapOfTokenGeneratorInstance.values().stream()
                    .map(TokenGeneratorInstance::getAnalyseTokensDialog)
                    .filter(Objects::nonNull)
                    .forEach(analyseTokensDialog -> analyseTokensDialog.setVisible(false));

            if (genTokensDialog != null) {
                genTokensDialog.setVisible(false);
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {
            mapOfTokenGeneratorInstance
                    .values()
                    .forEach(TokenGeneratorInstance::stopTokenGeneration);
        }
    }
}
