package com.example.custom.csp.filter;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for CustomContentSecurityPolicyFilter
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomContentSecurityPolicyFilter Unit Tests")
class CustomContentSecurityPolicyFilterTest {

	@Mock
	private HttpServletRequest mockRequest;

	@Mock
	private HttpServletResponse mockResponse;

	@Mock
	private FilterChain mockFilterChain;

	private CustomContentSecurityPolicyFilter filter;

	@BeforeEach
	void setUp() {
		filter = new CustomContentSecurityPolicyFilter();
	}

	@Test
	@DisplayName("Should modify CSP header for partnerportal domain")
	void testModifyCspHeaderForPartnerportalDomain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn("script-src 'nonce-ABC123def456'; style-src 'nonce-XYZ789'");

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockResponse).setHeader(
			eq("Content-Security-Policy"),
			contains("unsafe-inline"));
	}

	@Test
	@DisplayName("Should NOT modify CSP header for non-partnerportal domain")
	void testDoNotModifyCspHeaderForNonPartnerportalDomain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("www.example.com");
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn("script-src 'nonce-ABC123def456'");

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockResponse, never()).setHeader(
			eq("Content-Security-Policy"),
			anyString());
	}

	@ParameterizedTest
	@ValueSource(strings = {
		"partnerportal.example.com",
		"partnerportal-test.example.com",
		"partnerportal.staging.example.com"
	})
	@DisplayName("Should modify CSP for various partnerportal subdomains")
	void testModifyCspForVariousPartnerportalDomains(String domain) throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn(domain);
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn("script-src 'nonce-TEST123'");

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockResponse).setHeader(
			eq("Content-Security-Policy"),
			contains("unsafe-inline"));
	}

	@Test
	@DisplayName("Should replace nonce with unsafe-inline in CSP header")
	void testNonceReplacedWithUnsafeInline() throws Exception {
		// Arrange
		String originalCsp = "script-src 'nonce-ABC123def456'; style-src 'nonce-XYZ789qwer'";
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn(originalCsp);

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockResponse).setHeader(
			eq("Content-Security-Policy"),
			argThat(header -> 
				!header.contains("nonce-") && header.contains("unsafe-inline")));
	}

	@Test
	@DisplayName("Should handle Content-Security-Policy-Report-Only header")
	void testModifyCspReportOnlyHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		when(mockResponse.getHeader("Content-Security-Policy-Report-Only"))
			.thenReturn("script-src 'nonce-ABC123def456'");

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockResponse).setHeader(
			eq("Content-Security-Policy-Report-Only"),
			contains("unsafe-inline"));
	}

	@Test
	@DisplayName("Should handle null CSP header gracefully")
	void testHandleNullCspHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn(null);

		// Act & Assert
		assertThatNoException().isThrownBy(() ->
			filter.doFilter(mockRequest, mockResponse, mockFilterChain));
	}

	@Test
	@DisplayName("Should handle empty CSP header gracefully")
	void testHandleEmptyCspHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		when(mockResponse.getHeader("Content-Security-Policy"))
			.thenReturn("");

		// Act & Assert
		assertThatNoException().isThrownBy(() ->
			filter.doFilter(mockRequest, mockResponse, mockFilterChain));
	}

	@Test
	@DisplayName("Should call next filter in chain")
	void testCallNextFilterInChain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("example.com");

		// Act
		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		// Assert
		verify(mockFilterChain).doFilter(mockRequest, mockResponse);
	}
}