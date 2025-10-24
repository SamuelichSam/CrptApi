package ru.samuelich;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Thread-safe клиент для работы с API Честного знака (ГИС МТ)
 * с поддержкой ограничения количества запросов (rate limiting)
 *
 * Пример использования:
 * <pre>
 * {@code
 * CrptApi api = new CrptApi(TimeUnit.MINUTES, 10);
 * try {
 *     String documentId = api.createDocument(document, signature, token);
 * } finally {
 *     api.close();
 * }
 * }
 * </pre>
 */
public class CrptApi {

    private final TimeUnit timeUnit;
    private final int requestLimit;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Lock lock;
    private long lastRequestTime;
    private int requestCount;

    private static final String BASE_URL = "https://ismp.crpt.ru/api/v3";
    private static final String CREATE_DOCUMENT_URL = BASE_URL + "/lk/documents/create";
    private static final String AUTH_REQUEST_URL = BASE_URL + "/auth/cert/key";
    private static final String AUTH_CONFIRM_URL = BASE_URL + "/auth/cert/";

    /**
     * Создает экземпляр API клиента с ограничением запросов
     *
     * @param timeUnit    временной интервал для ограничения
     * @param requestLimit максимальное количество запросов в указанном интервале
     * @throws IllegalArgumentException если requestLimit <= 0
     */
    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        if (requestLimit <= 0) {
            throw new IllegalArgumentException("requestLimit должен быть положительным числом");
        }
        this.timeUnit = timeUnit;
        this.requestLimit = requestLimit;
        this.httpClient = HttpClients.createDefault();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.lock = new ReentrantLock();
        this.lastRequestTime = System.currentTimeMillis();
        this.requestCount = 0;
    }

    /**
     * Создает документ для ввода в оборот товара, произведенного в РФ
     *
     * @param document  документ для создания
     * @param signature подпись документа (УКЭП в base64)
     * @param token     аутентификационный токен
     * @return идентификатор созданного документа
     * @throws ApiException в случае ошибки API или сети
     */
    public String createDocument(Document document, String signature, String token) {
        waitIfNeeded();

        try {
            DocumentRequest request = new DocumentRequest(document, signature);
            String requestBody = objectMapper.writeValueAsString(request);

            HttpPost httpPost = new HttpPost(CREATE_DOCUMENT_URL);
            httpPost.setHeader("Authorization", "Bearer " + token);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("User-Agent", "CrptApi/1.0");
            httpPost.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);

                if (response.getCode() == 200) {
                    DocumentResponse docResponse = objectMapper.readValue(responseBody, DocumentResponse.class);
                    if (docResponse.isSuccess()) {
                        return docResponse.getValue();
                    } else {
                        throw new ApiException("Ошибка API: " + docResponse.getErrorMessage());
                    }
                } else {
                    throw new ApiException("Ошибка при создании документа. HTTP код: " + response.getCode() + ". Ответ: " + responseBody);
                }
            }
        } catch (JsonProcessingException e) {
            throw new ApiException("Ошибка сериализации документа", e);
        } catch (IOException e) {
            throw new ApiException("Ошибка при выполнении HTTP запроса", e);
        }
    }

    /**
     * Запрашивает данные для аутентификации (UUID и строку для подписи)
     *
     * @return объект с данными для аутентификации
     * @throws ApiException в случае ошибки сети или API
     */
    public AuthChallenge requestAuthChallenge() {
        waitIfNeeded();

        try {
            HttpGet httpGet = new HttpGet(AUTH_REQUEST_URL);

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                String responseBody = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);

                if (response.getCode() == 200) {
                    return objectMapper.readValue(responseBody, AuthChallenge.class);
                } else {
                    throw new ApiException("Ошибка запроса аутентификации. HTTP код: " + response.getCode());
                }
            }
        } catch (IOException e) {
            throw new ApiException("Ошибка при запросе аутентификации", e);
        }
    }

    /**
     * Выполняет аутентификацию с использованием подписанных данных
     *
     * @param uuid      UUID из запроса аутентификации
     * @param signedData подписанные данные (УКЭП в base64)
     * @return аутентификационный токен
     * @throws ApiException в случае ошибки аутентификации
     */
    public String authenticate(String uuid, String signedData) {
        waitIfNeeded();

        try {
            AuthRequest authRequest = new AuthRequest(uuid, signedData);
            String requestBody = objectMapper.writeValueAsString(authRequest);

            HttpPost httpPost = new HttpPost(AUTH_CONFIRM_URL);
            httpPost.setHeader("Content-Type", "application/json;charset=UTF-8");
            httpPost.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);

                if (response.getCode() == 200) {
                    AuthResponse authResponse = objectMapper.readValue(responseBody, AuthResponse.class);
                    return authResponse.getToken();
                } else {
                    throw new ApiException("Ошибка аутентификации. HTTP код: " + response.getCode() + ". Ответ: " + responseBody);
                }
            }
        } catch (IOException e) {
            throw new ApiException("Ошибка при аутентификации", e);
        }
    }

    /**
     * Закрывает ресурсы HTTP клиента
     * Должен вызываться после завершения работы с API
     */
    public void close() {
        try {
            httpClient.close();
        } catch (IOException e) {
            System.err.println("Ошибка при закрытии HTTP клиента: " + e.getMessage());
        }
    }

    private void waitIfNeeded() {
        lock.lock();
        try {
            long currentTime = System.currentTimeMillis();
            long timeWindow = timeUnit.toMillis(1);

            if (currentTime - lastRequestTime > timeWindow) {
                requestCount = 0;
                lastRequestTime = currentTime;
            }

            if (requestCount >= requestLimit) {
                long waitTime = lastRequestTime + timeWindow - currentTime;
                if (waitTime > 0) {
                    try {
                        Thread.sleep(waitTime);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new ApiException("Поток был прерван во время ожидания", e);
                    }
                }
                requestCount = 0;
                lastRequestTime = System.currentTimeMillis();
            }

            requestCount++;
        } finally {
            lock.unlock();
        }
    }

    // Модели данных
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthChallenge {
        @JsonProperty("uuid")
        private String uuid;
        @JsonProperty("data")
        private String data;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthRequest {
        @JsonProperty("uuid")
        private String uuid;
        @JsonProperty("data")
        private String data;
    }

    @Data
    @NoArgsConstructor
    public static class AuthResponse {
        @JsonProperty("token")
        private String token;
        @JsonProperty("code")
        private String code;
        @JsonProperty("error_message")
        private String errorMessage;
        @JsonProperty("description")
        private String description;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    public static class Document {
        @JsonProperty("description")
        private Description description;
        @JsonProperty("doc_id")
        private String docId;
        @JsonProperty("doc_status")
        private String docStatus;
        @JsonProperty("doc_type")
        private String docType;
        @JsonProperty("importRequest")
        private Boolean importRequest;
        @JsonProperty("owner_inn")
        private String ownerInn;
        @JsonProperty("participant_inn")
        private String participantInn;
        @JsonProperty("producer_inn")
        private String producerInn;
        @JsonProperty("production_date")
        private String productionDate;
        @JsonProperty("production_type")
        private String productionType;
        @JsonProperty("products")
        private Product[] products;
        @JsonProperty("reg_date")
        private String regDate;
        @JsonProperty("reg_number")
        private String regNumber;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    public static class Description {
        @JsonProperty("participantInn")
        private String participantInn;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Accessors(chain = true)
    public static class Product {
        @JsonProperty("certificate_document")
        private String certificateDocument;
        @JsonProperty("certificate_document_date")
        private String certificateDocumentDate;
        @JsonProperty("certificate_document_number")
        private String certificateDocumentNumber;
        @JsonProperty("owner_inn")
        private String ownerInn;
        @JsonProperty("producer_inn")
        private String producerInn;
        @JsonProperty("production_date")
        private String productionDate;
        @JsonProperty("tnved_code")
        private String tnvedCode;
        @JsonProperty("uit_code")
        private String uitCode;
        @JsonProperty("uitu_code")
        private String uituCode;
    }

    @Data
    @NoArgsConstructor
    @Accessors(chain = true)
    public static class DocumentRequest {
        @JsonProperty("document_format")
        private String documentFormat;
        @JsonProperty("product_document")
        private String productDocument;
        @JsonProperty("product_group")
        private String productGroup;
        @JsonProperty("signature")
        private String signature;
        @JsonProperty("type")
        private String type;

        public DocumentRequest(Document document, String signature) {
            this.documentFormat = "MANUAL";
            this.productGroup = "clothes";
            this.signature = signature;
            this.type = "LP_INTRODUCE_GOODS";

            try {
                ObjectMapper mapper = new ObjectMapper();
                String documentJson = mapper.writeValueAsString(document);
                this.productDocument = Base64.getEncoder().encodeToString(documentJson.getBytes());
            } catch (JsonProcessingException e) {
                throw new ApiException("Ошибка сериализации документа", e);
            }
        }
    }

    @Data
    @NoArgsConstructor
    @Accessors(chain = true)
    public static class DocumentResponse {
        @JsonProperty("value")
        private String value;
        @JsonProperty("code")
        private String code;
        @JsonProperty("error_message")
        private String errorMessage;
        @JsonProperty("description")
        private String description;

        public boolean isSuccess() {
            return value != null && !value.isEmpty();
        }
    }

    /**
     * Исключение для ошибок API
     */
    public static class ApiException extends RuntimeException {
        public ApiException(String message) {
            super(message);
        }
        public ApiException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}