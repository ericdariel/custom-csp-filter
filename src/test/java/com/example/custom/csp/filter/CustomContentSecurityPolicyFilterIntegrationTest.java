package com.example.custom.csp.filter;

import static org.assertj.core.api.Assertions.*;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Integration tests for CustomContentSecurityPolicyFilter
 */
@DisplayName("CustomContentSecurityPolicyFilter Integration Tests")
class CustomContentSecurityPolicyFilterIntegrationTest {

	private Filter filter;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain filterChain;

	@BeforeEach
	void setUp() {
		filter = new CustomContentSecurityPolicyFilter();
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		filterChain = new MockFilterChain();
	}

	@Test
	@DisplayName("Should modify real servlet response for partnerportal domain")
	void testRealServletResponseModification() throws Exception {
		// Arrange
		request.setServerName("partnerportal.example.com");
		String originalCsp = "script-src 'nonce-1234567890abcdef'; style-src 'nonce-abcdef1234567890'";
		response.setHeader("Content-Security-Policy", originalCsp);

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		String modifiedCsp = response.getHeader("Content-Security-Policy");
		assertThat(modifiedCsp)
			.contains("unsafe-inline")
			.doesNotContain("nonce-");
	}

	@Test
	@DisplayName("Should preserve other headers intact")
	void testPreserveOtherHeaders() throws Exception {
		// Arrange
		request.setServerName("partnerportal.example.com");
		response.setHeader("Content-Security-Policy", "script-src 'nonce-test123'");
		response.setHeader("X-Custom-Header", "custom-value");
		response.setHeader("Content-Type", "text/html; charset=UTF-8");

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		assertThat(response.getHeader("X-Custom-Header"))
			.isEqualTo("custom-value");
		assertThat(response.getHeader("Content-Type"))
			.isEqualTo("text/html; charset=UTF-8");
	}

	@Test
	@DisplayName("Should handle complex CSP policies")
	void testHandleComplexCspPolicy() throws Exception {
		// Arrange
		request.setServerName("partnerportal.staging.example.com");
		String complexCsp = "default-src 'self'; " +
			"script-src 'self' 'nonce-ABC123' https://trusted.com; " +
			"style-src 'self' 'nonce-XYZ789' 'unsafe-inline'; " +
			"img-src * data:; " +
			"font-src 'self' data:";
		response.setHeader("Content-Security-Policy", complexCsp);

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		String modifiedCsp = response.getHeader("Content-Security-Policy");
		assertThat(modifiedCsp)
			.contains("default-src 'self'")
			.contains("unsafe-inline")
			.doesNotContain("nonce-ABC123")
			.doesNotContain("nonce-XYZ789");
	}

	@Test
	@DisplayName("Should not modify for non-matching domain")
	void testNoModificationForNonMatchingDomain() throws Exception {
		// Arrange
		request.setServerName("api.example.com");
		String originalCsp = "script-src 'nonce-test123'";
		response.setHeader("Content-Security-Policy", originalCsp);

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		String modifiedCsp = response.getHeader("Content-Security-Policy");
		assertThat(modifiedCsp)
			.isEqualTo(originalCsp);
	}

	@Test
	@DisplayName("Should handle Report-Only policy in integration")
	void testHandleReportOnlyPolicyIntegration() throws Exception {
		// Arrange
		request.setServerName("partnerportal.example.com");
		String reportOnlyCsp = "script-src 'nonce-report123'; report-uri /csp-report";
		response.setHeader("Content-Security-Policy-Report-Only", reportOnlyCsp);

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		String modifiedCsp = response.getHeader("Content-Security-Policy-Report-Only");
		assertThat(modifiedCsp)
			.contains("unsafe-inline")
			.contains("report-uri /csp-report")
			.doesNotContain("nonce-");
	}

	@Test
	@DisplayName("Should handle multiple nonces in single directive")
	void testMultipleNoncesInSingleDirective() throws Exception {
		// Arrange
		request.setServerName("partnerportal.example.com");
		String cspWithMultipleNonces = "script-src 'nonce-nonce1234567890' 'nonce-nonce0987654321' https://example.com";
		response.setHeader("Content-Security-Policy", cspWithMultipleNonces);

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		String modifiedCsp = response.getHeader("Content-Security-Policy");
		assertThat(modifiedCsp)
			.contains("unsafe-inline")
			.doesNotContain("nonce-");
	}

	@Test
	@DisplayName("Should continue filter chain")
	void testFilterChainContinues() throws Exception {
		// Arrange
		request.setServerName("partnerportal.example.com");
		response.setHeader("Content-Security-Policy", "script-src 'nonce-test'");

		// Act
		filter.doFilter(request, response, filterChain);

		// Assert
		assertThat(filterChain.getRequest()).isNotNull();
		assertThat(filterChain.getResponse()).isNotNull();
	}
}