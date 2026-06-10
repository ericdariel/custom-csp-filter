package com.example.custom.csp.filter;

import static org.assertj.core.api.Assertions.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomContentSecurityPolicyFilter
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomContentSecurityPolicyFilter Unit Tests")
class CustomContentSecurityPolicyFilterTest {

	@Mock
	private HttpServletRequest mockRequest;

	@Mock
	private FilterChain mockFilterChain;

	private CustomContentSecurityPolicyFilterTestHelper filter;

	@BeforeEach
	void setUp() {
		filter = new CustomContentSecurityPolicyFilterTestHelper();
	}

	@Test
	@DisplayName("Should modify CSP header for partnerportal domain")
	void testModifyCspHeaderForPartnerportalDomain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy", "script-src 'nonce-ABC123def456'; style-src 'nonce-XYZ789'");

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		String cspHeader = response.getHeader("Content-Security-Policy");
		assertThat(cspHeader)
			.contains("unsafe-inline")
			.doesNotContain("nonce-");
	}

	@Test
	@DisplayName("Should NOT modify CSP header for non-partnerportal domain")
	void testDoNotModifyCspHeaderForNonPartnerportalDomain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("www.example.com");
		
		String originalCsp = "script-src 'nonce-ABC123def456'";
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy", originalCsp);

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		String cspHeader = response.getHeader("Content-Security-Policy");
		assertThat(cspHeader).isEqualTo(originalCsp);
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
		
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy", "script-src 'nonce-TEST123'");

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		assertThat(response.getHeader("Content-Security-Policy"))
			.contains("unsafe-inline");
	}

	@Test
	@DisplayName("Should replace nonce with unsafe-inline in CSP header")
	void testNonceReplacedWithUnsafeInline() throws Exception {
		// Arrange
		String originalCsp = "script-src 'nonce-ABC123def456'; style-src 'nonce-XYZ789qwer'";
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy", originalCsp);

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		String cspHeader = response.getHeader("Content-Security-Policy");
		assertThat(cspHeader)
			.doesNotContain("nonce-")
			.contains("unsafe-inline");
	}

	@Test
	@DisplayName("Should handle Content-Security-Policy-Report-Only header")
	void testModifyCspReportOnlyHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy-Report-Only", "script-src 'nonce-ABC123def456'");

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		assertThat(response.getHeader("Content-Security-Policy-Report-Only"))
			.contains("unsafe-inline");
	}

	@Test
	@DisplayName("Should handle null CSP header gracefully")
	void testHandleNullCspHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();

		// Act & Assert
		assertThatNoException().isThrownBy(() ->
			filter.processFilterPublic(mockRequest, response, mockFilterChain));
	}

	@Test
	@DisplayName("Should handle empty CSP header gracefully")
	void testHandleEmptyCspHeader() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("partnerportal.example.com");
		
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();
		response.setHeader("Content-Security-Policy", "");

		// Act & Assert
		assertThatNoException().isThrownBy(() ->
			filter.processFilterPublic(mockRequest, response, mockFilterChain));
	}

	@Test
	@DisplayName("Should call next filter in chain")
	void testCallNextFilterInChain() throws Exception {
		// Arrange
		when(mockRequest.getServerName()).thenReturn("example.com");
		TestHttpServletResponseWrapper response = new TestHttpServletResponseWrapper();

		// Act
		filter.processFilterPublic(mockRequest, response, mockFilterChain);

		// Assert
		verify(mockFilterChain).doFilter(mockRequest, response);
	}

	/**
	 * Test helper class that exposes processFilter method
	 */
	static class CustomContentSecurityPolicyFilterTestHelper extends CustomContentSecurityPolicyFilter {
		
		public void processFilterPublic(
			HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws Exception {
			
			processFilter(httpServletRequest, httpServletResponse, filterChain);
		}
	}

	/**
	 * Simple response wrapper for testing
	 */
	static class TestHttpServletResponseWrapper extends HttpServletResponseWrapper {
		
		private java.util.Map<String, String> headers = new java.util.HashMap<>();
		
		public TestHttpServletResponseWrapper() {
			super(new org.springframework.mock.web.MockHttpServletResponse());
		}
		
		@Override
		public void setHeader(String name, String value) {
			headers.put(name, value);
			super.setHeader(name, value);
		}
		
		@Override
		public String getHeader(String name) {
			return headers.getOrDefault(name, super.getHeader(name));
		}
	}
}