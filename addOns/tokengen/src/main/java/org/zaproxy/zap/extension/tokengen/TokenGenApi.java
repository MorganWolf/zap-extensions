/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import java.math.RoundingMode;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

public class TokenGenApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(TokenGenApi.class);

    private static final String REQUEST_HISTORY_ID = "requestHistoryId";
    private static final String NUMBER_OF_TOKENS = "numberOfToken";
    private static final String TOKEN_TYPE = "tokenType";
    private static final String TOKEN_NAME = "tokenName";

    private static final String RUN_UUID = "runInstanceUuid";
    private static final String STATUS = "status";
    private static final String STATUS_RUNNING = "running";
    private static final String STATUS_DONE = "done";
    private static final String PERCENTAGE_GENERATED_TOKEN = "percentageOfGeneratedTokens";
    private static final String DETAILS_RESULT = "details";

    private static final String PREFIX = "tokengen";
    private static final String START_TOKEN_GENERATION = "startTokenGeneration";
    private static final String RUN_RESULT = "runResult";
    private static final String VERSION = "version";

    private final ExtensionTokenGen extension;

    public TokenGenApi(ExtensionTokenGen extension) {
        super();
        this.extension = extension;
        this.addApiAction(
                new ApiAction(
                        START_TOKEN_GENERATION,
                        new String[] {
                            REQUEST_HISTORY_ID, NUMBER_OF_TOKENS, TOKEN_NAME, TOKEN_TYPE
                        }));
        this.addApiView(new ApiView(RUN_RESULT, new String[] {RUN_UUID}));
        this.addApiView(new ApiView(VERSION));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiAction {} {}", name, params);

        if (name.equals(START_TOKEN_GENERATION)) {
            try {
                var htmlParameterStats =
                        new HtmlParameterStats(
                                null,
                                (String) params.get(TOKEN_NAME),
                                HtmlParameter.Type.valueOf((String) params.get(TOKEN_TYPE)),
                                null,
                                null);
                ExtensionHistory extHistory =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.class);

                int historyId = Integer.parseInt((String) params.get(REQUEST_HISTORY_ID));
                var historyReference = extHistory.getHistoryReference(historyId);
                if (historyReference == null) {
                    throw new ApiException(
                            ApiException.Type.DOES_NOT_EXIST,
                            String.format("The history id '%s' does not exist.", historyId));
                }
                var msg = historyReference.getHttpMessage();
                UUID runInstanceUuid = this.extension.createTokenGeneratorInstance();
                TokenGeneratorInstance tokenGeneratorInstance =
                        this.extension.mapOfTokenGeneratorInstance.get(runInstanceUuid);
                tokenGeneratorInstance.startTokenGeneration(
                        msg,
                        Integer.parseInt((String) params.get(NUMBER_OF_TOKENS)),
                        htmlParameterStats,
                        true);
                return new ApiResponseElement(RUN_UUID, runInstanceUuid.toString());
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST, e.getMessage());
            }
        }
        throw new ApiException(ApiException.Type.BAD_ACTION);
    }

    @Override
    public ApiResponse handleApiOptionView(String name, JSONObject params) throws ApiException {
        if (name.equals(RUN_RESULT)) {
            int NUMBER_OF_DETAILS_OBJECT = 9;
            UUID runUuid = UUID.fromString((String) params.get(RUN_UUID));
            TokenGeneratorInstance tokenGeneratorInstance =
                    this.extension.getMapOfTokenGeneratorInstance().get(runUuid);
            if (tokenGeneratorInstance == null) {
                throw new ApiException(
                        ApiException.Type.DOES_NOT_EXIST,
                        String.format("UUID '%s' does not exist.", runUuid));
            }
            double currentGeneratedToken = tokenGeneratorInstance.getCfm().getTokens().size();
            double maxTokens = tokenGeneratorInstance.getNumberOfTokens();
            NumberFormat nf = NumberFormat.getNumberInstance();
            nf.setRoundingMode(RoundingMode.HALF_UP);
            String roundedPercentageOfTokens = nf.format((currentGeneratedToken / maxTokens) * 100);
            List<TokenAnalysisTestResult> tokenAnalysisTestResults =
                    tokenGeneratorInstance.getTokenAnalysisTestResult();
            Object detailsResult = tokenAnalysisTestResults;
            if (!tokenAnalysisTestResults.isEmpty()
                    && tokenAnalysisTestResults.size() < NUMBER_OF_DETAILS_OBJECT) {
                detailsResult = "processing...";
            }
            String status =
                    tokenGeneratorInstance.getRunningGenerators() > 0
                            ? STATUS_RUNNING
                            : STATUS_DONE;
            ApiResponseSet<Object> result = new ApiResponseSet<>("result", new HashMap<>());
            result.put(STATUS, status);
            result.put(PERCENTAGE_GENERATED_TOKEN, roundedPercentageOfTokens);
            result.put(DETAILS_RESULT, detailsResult);
            return result;
        }
        if (name.equals(VERSION)) {
            return new ApiResponseElement(VERSION, "v1.16");
        }
        throw new ApiException(ApiException.Type.BAD_VIEW);
    }
}
