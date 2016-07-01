/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.deploy.rest

import javax.servlet._
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}

/**
 * This filter provides protection against Form CSRF attack.
 */
private[spark] class FormCSRFPreventionFilter extends Filter {

  import FormCSRFPreventionFilter._

  def init(filterConfig: FilterConfig): Unit = {}

  def checkCSRF(servletRequest: ServletRequest): Boolean = {
    val httpReq = servletRequest.asInstanceOf[HttpServletRequest];
    val salt = httpReq.getParameter("csrfPreventionSalt").asInstanceOf[String]
    return salt == (httpReq.getRequestedSessionId + randomStr);
  }

  def doFilter(
      servletRequest: ServletRequest,
      servletResponse: ServletResponse,
      filterChain: FilterChain): Unit = {
    val httpReq = servletRequest.asInstanceOf[HttpServletRequest]
    if(ignoreMethods.contains(httpReq.getMethod) || checkCSRF(servletRequest)) {
      filterChain.doFilter(servletRequest, servletResponse)
    } else {
      servletResponse.asInstanceOf[HttpServletResponse].sendError(
        HttpServletResponse.SC_BAD_REQUEST, "Missing Required Header for CSRF protection.")
    }
  }

  def destroy(): Unit = {}
}

private[spark] object FormCSRFPreventionFilter {
  val randomStr = new java.security.SecureRandom().nextLong().toString()
  val ignoreMethods = Array("GET", "OPTIONS", "HEAD", "TRACE")
}

