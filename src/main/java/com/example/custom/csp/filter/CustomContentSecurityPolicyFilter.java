package com.example.custom.csp.filter;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.servlet.filters.BasePortalFilter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.osgi.service.component.annotations.Component;

/**
 * Custom CSP filter that modifies the CSP header based on the domain.
 * For domains starting with "partnerportal", replaces nonce values with 'unsafe-inline'.
 * 
 * @author Eric Daniel
 */
@Component(
	property = {
		"after-filter=Content Security Policy Filter",
		"dispatcher=FORWARD",
		"dispatcher=REQUEST",
		"servlet-context-name=",
		"servlet-filter-name=Custom Content Security Policy Filter",
		"url-pattern=/*"
	},
	service = Filter.class
)
public class CustomContentSecurityPolicyFilter extends BasePortalFilter {

	@Override
	protected void processFilter(
			HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			FilterChain filterChain)
		throws Exception {

		// Wrapper la response pour capturer les headers CSP
		HttpServletResponseWrapper wrappedResponse = 
			new CustomCspResponseWrapper(httpServletResponse);

		try {
			filterChain.doFilter(httpServletRequest, wrappedResponse);
		}
		finally {
			// Appliquer les modifications du CSP après Liferay
			_modifyCspHeader(httpServletRequest, wrappedResponse);
		}
	}

	/**
	 * Modifie les headers CSP en fonction du domaine
	 */
	private void _modifyCspHeader(
		HttpServletRequest httpServletRequest,
		HttpServletResponseWrapper wrappedResponse) {

		String serverName = httpServletRequest.getServerName();

		// Vérifier si le domaine commence par "partnerportal"
		if (serverName.startsWith("partnerportal")) {
			String cspHeader = wrappedResponse.getHeader(
				"Content-Security-Policy");
			String cspReportOnlyHeader = wrappedResponse.getHeader(
				"Content-Security-Policy-Report-Only");

			if (Validator.isNotNull(cspHeader)) {
				// Remplacer le nonce par unsafe-inline
				String modifiedCsp = cspHeader.replaceAll(
					"nonce-[A-Za-z0-9+/=]+", "unsafe-inline");

				if (_log.isDebugEnabled()) {
					_log.debug(
						"Modified CSP header for partnerportal domain: " + 
							serverName +
							"\nOriginal: " + cspHeader +
							"\nModified: " + modifiedCsp);
				}

				wrappedResponse.setHeader(
					"Content-Security-Policy", modifiedCsp);
			}

			if (Validator.isNotNull(cspReportOnlyHeader)) {
				String modifiedCsp = cspReportOnlyHeader.replaceAll(
					"nonce-[A-Za-z0-9+/=]+", "unsafe-inline");

				wrappedResponse.setHeader(
					"Content-Security-Policy-Report-Only", modifiedCsp);
			}
		}
	}

	private static final Log _log = LogFactoryUtil.getLog(
		CustomContentSecurityPolicyFilter.class);

	/**
	 * Wrapper personnalisé pour capturer et modifier les headers CSP
	 */
	private static class CustomCspResponseWrapper extends HttpServletResponseWrapper {

		private String _cspHeader;
		private String _cspReportOnlyHeader;

		public CustomCspResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public void setHeader(String name, String value) {
			if ("Content-Security-Policy".equals(name)) {
				_cspHeader = value;
			}
			else if ("Content-Security-Policy-Report-Only".equals(name)) {
				_cspReportOnlyHeader = value;
			}

			super.setHeader(name, value);
		}

		@Override
		public String getHeader(String name) {
			if ("Content-Security-Policy".equals(name)) {
				return _cspHeader;
			}
			else if ("Content-Security-Policy-Report-Only".equals(name)) {
				return _cspReportOnlyHeader;
			}

			return super.getHeader(name);
		}
	}
}