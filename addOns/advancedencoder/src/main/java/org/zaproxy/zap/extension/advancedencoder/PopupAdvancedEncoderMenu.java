/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.advancedencoder;

import java.awt.Component;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

public class PopupAdvancedEncoderMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private JTextComponent lastInvoker = null;

    /** This method initializes */
    public PopupAdvancedEncoderMenu() {
        super();
        initialize();
    }

    /** @return Returns the lastInvoker. */
    public JTextComponent getLastInvoker() {
        return lastInvoker;
    }

    /** @param lastInvoker The lastInvoker to set. */
    public void setLastInvoker(JTextComponent lastInvoker) {
        this.lastInvoker = lastInvoker;
    }

    /** This method initializes this */
    private void initialize() {
        this.setText(Constant.messages.getString("advancedencoder.tools.menu.encdec"));
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTextComponent && !isInvokerFromEncodeDecode(invoker)) {

            JTextComponent txt = (JTextComponent) invoker;
            String sel = txt.getSelectedText();
            if (sel == null || sel.length() == 0) {
                this.setEnabled(false);
            } else {
                this.setEnabled(true);
            }

            setLastInvoker((JTextComponent) invoker);
            return true;
        } else {
            setLastInvoker(null);
            return false;
        }
    }

    private boolean isInvokerFromEncodeDecode(Component invoker) {
        if (invoker.getName() == null) {
            return false;
        } else {
            return invoker.getName().equals(AdvancedEncodeDecodeDialog.ENCODE_DECODE_FIELD)
                    || invoker.getName()
                            .equals(AdvancedEncodeDecodeDialog.ENCODE_DECODE_RESULTFIELD);
        }
    }
}
