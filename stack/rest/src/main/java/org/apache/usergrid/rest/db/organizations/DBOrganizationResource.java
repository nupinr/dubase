/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.usergrid.rest.db.organizations;


import org.apache.shiro.authz.UnauthorizedException;
import org.apache.usergrid.management.OrganizationInfo;
import org.apache.usergrid.management.export.ExportService;
import org.apache.usergrid.persistence.Query;
import org.apache.usergrid.persistence.index.query.Identifier;
import org.apache.usergrid.rest.AbstractContextResource;
import org.apache.usergrid.rest.applications.ApplicationResource;
import org.apache.usergrid.rest.applications.ServiceResource;
import org.apache.usergrid.rest.applications.users.UserResource;
import org.apache.usergrid.rest.db.organizations.users.DBUsersResource;
import org.apache.usergrid.rest.exceptions.NoOpException;
import org.apache.usergrid.rest.exceptions.OrganizationApplicationNotFoundException;
import org.apache.usergrid.rest.exceptions.RedirectionException;
import org.apache.usergrid.rest.management.organizations.applications.ApplicationsResource;
import org.apache.usergrid.rest.utils.PathingUtils;
import org.apache.usergrid.security.shiro.utils.SubjectUtils;
import org.apache.usergrid.security.tokens.exceptions.TokenException;
import org.apache.usergrid.services.ServiceParameter;
import org.apache.usergrid.utils.UUIDUtils;
import org.glassfish.jersey.server.mvc.Viewable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import static org.apache.usergrid.services.ServiceParameter.addParameter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.UriInfo;


@Component("org.apache.usergrid.rest.db.organizations.DBOrganizationResource")
@Scope("prototype")
@Produces({
	MediaType.APPLICATION_JSON, "application/javascript", "application/x-javascript", "text/ecmascript",
	"application/ecmascript", "text/jscript"
})
public class DBOrganizationResource extends AbstractContextResource {

	private static final Logger logger = LoggerFactory.getLogger( DBOrganizationsResource.class );

	@Autowired
	protected ExportService exportService;

	OrganizationInfo organization;


	public DBOrganizationResource() {
		if (logger.isTraceEnabled()) {
			logger.trace("OrganizationResource created");
		}
	}


	public DBOrganizationResource init( OrganizationInfo organization ) {
		this.organization = organization;
		if (logger.isTraceEnabled()) {
			logger.trace("OrganizationResource initialized for org {}", organization.getName());
		}
		return this;
	}


	@Path("users")
	public DBUsersResource getOrganizationUsers( @Context UriInfo ui ) throws Exception {
		return getSubResource( DBUsersResource.class ).init( organization );
	}

	@Path("applications")
	public ApplicationsResource getOrganizationApplications( @Context UriInfo ui ) throws Exception {
		return getSubResource( ApplicationsResource.class ).init( organization );
	}

	@Path("{applicationName}")
	public ApplicationResource getApplicationByName( @PathParam("applicationName") String applicationName )
			throws Exception {

		if (logger.isTraceEnabled()) {
			logger.trace("getApplicationByName: {}", applicationName);
		}

		if ( "options".equalsIgnoreCase( request.getMethod() ) ) {
			throw new NoOpException();
		}

		String orgAppName = PathingUtils.assembleAppName( organization.getName(), applicationName );
		UUID optionalAppId = emf.lookupApplication( orgAppName );

		if ( optionalAppId == null ) {

			// TODO: fix this hacky work-around for apparent Jersey issue
			UUID applicationId = UUIDUtils.tryExtractUUID( applicationName );

			if ( applicationId == null ) {
				throw new OrganizationApplicationNotFoundException( orgAppName, uriInfo, properties, management );
			}else{
				optionalAppId = applicationId;
			}
		}

		return appResourceFor( optionalAppId );
	}

	@Path("applications/{applicationName}")
	public ApplicationResource getApplicationByName2( @PathParam("applicationName") String applicationName )
			throws Exception {
		return getApplicationByName( applicationName );
	}

	@Path("apps/{applicationName}")
	public ApplicationResource getApplicationByName3( @PathParam("applicationName") String applicationName )
			throws Exception {
		return getApplicationByName( applicationName );
	}

	private ApplicationResource appResourceFor( UUID applicationId ) throws Exception {
		if ( applicationId.equals( emf.getManagementAppId() ) && !SubjectUtils.isServiceAdmin() ) {
			throw new UnauthorizedException();
		}

		return getSubResource( ApplicationResource.class ).init( applicationId );
	}

	@GET
	@Path("activate")
	@Produces(MediaType.TEXT_HTML)
	public Viewable activate( @Context UriInfo ui, @QueryParam("token") String token ) {

		try {
			management.handleActivationTokenForOrganization( organization.getUuid(), token );
			return handleViewable( "activate", this, organization.getName() );
		}
		catch ( TokenException e ) {
			return handleViewable( "bad_activation_token", this, organization.getName() );
		}
		catch ( RedirectionException e ) {
			throw e;
		}
		catch ( Exception e ) {
			return handleViewable( "error", e, organization.getName() );
		}
	}
}
