/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.tomcat.ext.transport;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.security.SecurityUtil;
import org.apache.tomcat.util.http.ServerCookie;
import org.wso2.carbon.core.SameSiteCookie;
import org.wso2.carbon.core.ServletCookie;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Locale;

/**
 *  This CarbonResponseWrapper handle the responses and generates headers with sameSite attribute value.
 */
public class CarbonResponseWrapper extends Response {

    private Response wrapped;
    private ResponseFacadeWrapper responseFacadeWrapper;

    public CarbonResponseWrapper(Response wrapped) {
        this.wrapped = wrapped;
    }

    public Response getWrapped() {
        return wrapped;
    }

    @Override
    public StringBuffer generateCookieString(final Cookie cookie) {
        final StringBuffer cookieBuffer = new StringBuffer();
        if (SecurityUtil.isPackageProtectionEnabled()) {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                public Void run() {
                    appendCookieValue(cookie, cookieBuffer);
                    return null;
                }
            });
        } else {
            appendCookieValue(cookie, cookieBuffer);
        }
        return cookieBuffer;
    }

    /**
     * When "ServletCookie" uses to generate cookies, gets the sameSite value from ServletCookie and append it
     * into the cookieString, otherwise append sameSite value as "Strict" by default.
     *
     * @param cookie Cookie.
     * @return Set-Cookie string value generated using cookie attributes.
     */
    private void appendCookieValue(Cookie cookie, StringBuffer sb) {
        if (cookie instanceof ServletCookie) {
            ServerCookie.appendCookieValue(sb, cookie.getVersion(), cookie.getName(), cookie.getValue(),
                    cookie.getPath(), cookie.getDomain(), cookie.getComment(), cookie.getMaxAge(), cookie.getSecure(),
                    cookie.isHttpOnly());
            sb.append("; SameSite=").append(((ServletCookie) cookie).getSameSite().toPrintable());
        } else {
            ServerCookie.appendCookieValue(sb, cookie.getVersion(), cookie.getName(), cookie.getValue(),
                    cookie.getPath(), cookie.getDomain(), cookie.getComment(), cookie.getMaxAge(), cookie.getSecure(),
                    cookie.isHttpOnly());
            sb.append("; SameSite=").append(SameSiteCookie.STRICT.toPrintable());
        }
    }

    @Override
    @Deprecated
    public Connector getConnector() {
        return wrapped.getConnector();
    }

    @Override
    public void setConnector(Connector connector) {
        wrapped.setConnector(connector);
    }

    @Override
    public void setCoyoteResponse(org.apache.coyote.Response coyoteResponse) {
        wrapped.setCoyoteResponse(coyoteResponse);
    }

    @Override
    public org.apache.coyote.Response getCoyoteResponse() {
        return wrapped.getCoyoteResponse();
    }

    @Override
    public Context getContext() {
        return wrapped.getContext();
    }

    @Override
    @Deprecated
    public void setContext(Context context) {
        wrapped.setContext(context);
    }

    @Override
    public void recycle() {
        wrapped.recycle();
    }

    @Override
    public void clearEncoders() {
        wrapped.clearEncoders();
    }

    @Override
    public long getContentWritten() {
        return wrapped.getContentWritten();
    }

    @Override
    public long getBytesWritten(boolean flush) {
        return wrapped.getBytesWritten(flush);
    }

    @Override
    public void setAppCommitted(boolean appCommitted) {
        wrapped.setAppCommitted(appCommitted);
    }

    @Override
    public boolean isAppCommitted() {
        return wrapped.isAppCommitted();
    }

    @Override
    @Deprecated
    public boolean getIncluded() {
        return wrapped.getIncluded();
    }

    @Override
    @Deprecated
    public void setIncluded(boolean included) {
        wrapped.setIncluded(included);
    }

    @Override
    public String getInfo() {
        return wrapped.getInfo();
    }

    @Override
    public Request getRequest() {
        return wrapped.getRequest();
    }

    @Override
    public void setRequest(Request request) {
        wrapped.setRequest(request);
    }

    @Override
    public HttpServletResponse getResponse() {
        if(responseFacadeWrapper == null) {
            responseFacadeWrapper = new ResponseFacadeWrapper(this);
        }
        return responseFacadeWrapper;
    }

    @Override
    @Deprecated
    public OutputStream getStream() {
        return wrapped.getStream();
    }

    @Override
    public void setSuspended(boolean suspended) {
        wrapped.setSuspended(suspended);
    }

    @Override
    public boolean isSuspended() {
        return wrapped.isSuspended();
    }

    @Override
    public boolean isClosed() {
        return wrapped.isClosed();
    }

    @Override
    public boolean setError() {
        return wrapped.setError();
    }

    @Override
    public boolean isError() {
        return wrapped.isError();
    }

    @Override
    public boolean isErrorReportRequired() {
        return wrapped.isErrorReportRequired();
    }

    @Override
    public boolean setErrorReported() {
        return wrapped.setErrorReported();
    }

    @Override
    @Deprecated
    public ServletOutputStream createOutputStream() throws IOException {
        return wrapped.createOutputStream();
    }

    @Override
    public void finishResponse() throws IOException {
        wrapped.finishResponse();
    }

    @Override
    public int getContentLength() {
        return wrapped.getContentLength();
    }

    @Override
    public String getContentType() {
        return wrapped.getContentType();
    }

    @Override
    public PrintWriter getReporter() throws IOException {
        return wrapped.getReporter();
    }

    @Override
    public void flushBuffer() throws IOException {
        wrapped.flushBuffer();
    }

    @Override
    public int getBufferSize() {
        return wrapped.getBufferSize();
    }

    @Override
    public String getCharacterEncoding() {
        return wrapped.getCharacterEncoding();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return wrapped.getOutputStream();
    }

    @Override
    public Locale getLocale() {
        return wrapped.getLocale();
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return wrapped.getWriter();
    }

    @Override
    public boolean isCommitted() {
        return wrapped.isCommitted();
    }

    @Override
    public void reset() {
        wrapped.reset();
    }

    @Override
    public void resetBuffer() {
        wrapped.resetBuffer();
    }

    @Override
    public void resetBuffer(boolean resetWriterStreamFlags) {
        wrapped.resetBuffer(resetWriterStreamFlags);
    }

    @Override
    public void setBufferSize(int size) {
        wrapped.setBufferSize(size);
    }

    @Override
    public void setContentLength(int length) {
        wrapped.setContentLength(length);
    }

    @Override
    public void setContentType(String type) {
        wrapped.setContentType(type);
    }

    @Override
    public void setCharacterEncoding(String charset) {
        wrapped.setCharacterEncoding(charset);
    }

    @Override
    public void setLocale(Locale locale) {
        wrapped.setLocale(locale);
    }

    @Override
    public String getHeader(String name) {
        return wrapped.getHeader(name);
    }

    @Override
    public Collection<String> getHeaderNames() {
        return wrapped.getHeaderNames();
    }

    @Override
    public Collection<String> getHeaders(String name) {
        return wrapped.getHeaders(name);
    }

    @Override
    public String getMessage() {
        return wrapped.getMessage();
    }

    @Override
    public int getStatus() {
        return wrapped.getStatus();
    }

    @Override
    @Deprecated
    public void reset(int status, String message) {
        wrapped.reset(status, message);
    }

    @Override
    public void addCookie(Cookie cookie) {
        if (!wrapped.getIncluded() && !wrapped.isCommitted()) {
            StringBuffer sb = this.generateCookieString(cookie);
            this.addHeader("Set-Cookie", sb.toString());
        }
    }

    @Override
    public void addSessionCookieInternal(Cookie cookie) {
        wrapped.addSessionCookieInternal(cookie);
    }

    @Override
    public void addDateHeader(String name, long value) {
        wrapped.addDateHeader(name, value);
    }

    @Override
    public void addHeader(String name, String value) {
        wrapped.addHeader(name, value);
    }

    @Override
    public void addIntHeader(String name, int value) {
        wrapped.addIntHeader(name, value);
    }

    @Override
    public boolean containsHeader(String name) {
        return wrapped.containsHeader(name);
    }

    @Override
    public String encodeRedirectURL(String url) {
        return wrapped.encodeRedirectURL(url);
    }

    @Override
    @Deprecated
    public String encodeRedirectUrl(String url) {
        return wrapped.encodeRedirectUrl(url);
    }

    @Override
    public String encodeURL(String url) {
        return wrapped.encodeURL(url);
    }

    @Override
    @Deprecated
    public String encodeUrl(String url) {
        return wrapped.encodeUrl(url);
    }

    @Override
    public void sendAcknowledgement() throws IOException {
        wrapped.sendAcknowledgement();
    }

    @Override
    public void sendError(int status) throws IOException {
        wrapped.sendError(status);
    }

    @Override
    public void sendError(int status, String message) throws IOException {
        wrapped.sendError(status, message);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        wrapped.sendRedirect(location);
    }

    @Override
    public void sendRedirect(String location, int status) throws IOException {
        wrapped.sendRedirect(location, status);
    }

    @Override
    public void setDateHeader(String name, long value) {
        wrapped.setDateHeader(name, value);
    }

    @Override
    public void setHeader(String name, String value) {
        wrapped.setHeader(name, value);
    }

    @Override
    public void setIntHeader(String name, int value) {
        wrapped.setIntHeader(name, value);
    }

    @Override
    public void setStatus(int status) {
        wrapped.setStatus(status);
    }

    @Override
    @Deprecated
    public void setStatus(int status, String message) {
        wrapped.setStatus(status, message);
    }

}
