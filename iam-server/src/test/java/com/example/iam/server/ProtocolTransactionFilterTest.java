package com.example.iam.server;

import com.example.iam.server.token.ProtocolTransactionFilter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.web.context.request.RequestContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ProtocolTransactionFilterTest {
    @Test
    void commitFailureNeverPublishesBufferedToken() throws Exception {
        var transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        doThrow(new TransactionSystemException("injected commit failure")).when(transactions).commit(any());
        var request = new MockHttpServletRequest("POST", "/oauth2/token");
        var response = new MockHttpServletResponse();
        new ProtocolTransactionFilter(transactions, mock(org.springframework.jdbc.core.JdbcTemplate.class)).doFilter(request, response, (req, res) -> {
            res.setContentType("application/json");
            res.getWriter().write("{\"access_token\":\"must-never-be-published\"}");
            res.flushBuffer();
            assertFalse(response.getContentAsString().contains("must-never-be-published"));
        });
        assertEquals(503, response.getStatus());
        assertFalse(response.getContentAsString().contains("must-never-be-published"));
        assertTrue(response.getContentAsString().contains("temporarily_unavailable"));
        assertNull(RequestContextHolder.getRequestAttributes());
    }

    @Test
    void successfulResponseIsPublishedAfterCommit() throws Exception {
        var transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        var response = new MockHttpServletResponse();
        doAnswer(call -> {
            assertEquals("", response.getContentAsString());
            return null;
        })
                .when(transactions).commit(any());
        new ProtocolTransactionFilter(transactions, mock(org.springframework.jdbc.core.JdbcTemplate.class)).doFilter(new MockHttpServletRequest("POST", "/oauth2/token"),
                response, (req, res) -> res.getWriter().write("committed-response"));
        verify(transactions).commit(any());
        assertEquals("committed-response", response.getContentAsString());
    }
}
