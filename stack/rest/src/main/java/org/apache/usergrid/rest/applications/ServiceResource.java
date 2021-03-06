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
package org.apache.usergrid.rest.applications;


import com.amazonaws.AmazonServiceException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jaxrs.json.annotation.JSONP;
import org.apache.commons.lang.StringUtils;
import org.apache.usergrid.management.OrganizationConfig;
import org.apache.usergrid.management.OrganizationConfigProps;
import org.apache.usergrid.persistence.Entity;
import org.apache.usergrid.persistence.EntityManager;
import org.apache.usergrid.persistence.Query;
import org.apache.usergrid.persistence.QueryUtils;
import org.apache.usergrid.rest.AbstractContextResource;
import org.apache.usergrid.rest.ApiResponse;
import org.apache.usergrid.rest.RootResource;
import org.apache.usergrid.rest.applications.assets.AssetsResource;
import org.apache.usergrid.rest.security.annotations.CheckPermissionsForPath;
import org.apache.usergrid.security.oauth.AccessInfo;
import org.apache.usergrid.services.*;
import org.apache.usergrid.services.assets.data.AssetUtils;
import org.apache.usergrid.services.assets.data.AwsSdkS3BinaryStore;
import org.apache.usergrid.services.assets.data.BinaryStore;
import org.apache.usergrid.services.assets.data.LocalFileBinaryStore;
import org.apache.usergrid.services.exceptions.AwsPropertiesNotFoundException;
import org.apache.usergrid.utils.JsonUtils;
import org.glassfish.jersey.media.multipart.BodyPart;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import javax.ws.rs.*;
import javax.ws.rs.core.*;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.UUID;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import static org.apache.usergrid.management.AccountCreationProps.PROPERTIES_USERGRID_BINARY_UPLOADER;
import static org.apache.usergrid.utils.InflectionUtils.pluralize;


@Component
@Scope("prototype")
@Produces({
	MediaType.APPLICATION_JSON, "application/javascript", "application/x-javascript", "text/ecmascript",
	"application/ecmascript", "text/jscript"
})
public class ServiceResource extends AbstractContextResource {

	protected static final Logger logger = LoggerFactory.getLogger( ServiceResource.class );
	private static final String FILE_FIELD_NAME = "file";


	// @Autowired
	private BinaryStore binaryStore;

	@Autowired
	private LocalFileBinaryStore localFileBinaryStore;

	@Autowired
	private AwsSdkS3BinaryStore awsSdkS3BinaryStore;

	protected ServiceManager services;

	/*
	 * --Nupin--start--
	 */
	protected ServiceManager orgServices;
	/*
	 * --end--
	 */

	List<ServiceParameter> serviceParameters = null;


	public ServiceResource() {
	}


	public void setBinaryStore(String binaryStoreType){

		//TODO:GREY change this to be a property held elsewhere
		if(binaryStoreType.equals("local")){
			this.binaryStore = localFileBinaryStore;
		}
		else{
			this.binaryStore = awsSdkS3BinaryStore;
		}
	}


	@Override
	public void setParent( AbstractContextResource parent ) {
		super.setParent( parent );
		if ( parent instanceof ServiceResource ) {
			services = ( ( ServiceResource ) parent ).services;
		}
	}


	public ServiceResource getServiceResourceParent() {
		if ( parent instanceof ServiceResource ) {
			return ( ServiceResource ) parent;
		}
		return null;
	}


	public ServiceManager getServices() {
		return services;
	}


	public UUID getApplicationId() {
		return services.getApplicationId();
	}


	public String getOrganizationName() {
		return services.getApplication().getOrganizationName();
	}


	public List<ServiceParameter> getServiceParameters() {
		if ( serviceParameters != null ) {
			return serviceParameters;
		}
		if ( getServiceResourceParent() != null ) {
			return getServiceResourceParent().getServiceParameters();
		}
		serviceParameters = new ArrayList<>();
		return serviceParameters;
	}


	public static List<ServiceParameter> addMatrixParams( List<ServiceParameter> parameters, UriInfo ui,
			PathSegment ps ) throws Exception {

		MultivaluedMap<String, String> params = ps.getMatrixParameters();

		if ( params != null && params.size() > 0) {
			Query query = Query.fromQueryParams( params );
			if ( query != null ) {
				parameters = ServiceParameter.addParameter( parameters, query );
			}
		}

		return parameters;
	}


	public static List<ServiceParameter> addQueryParams( List<ServiceParameter> parameters, UriInfo ui )
			throws Exception {

		MultivaluedMap<String, String> params = ui.getQueryParameters();
		if ( params != null && params.size() > 0) {
			//TODO TN query parameters are not being correctly decoded here.  The URL encoded strings
			//aren't getting decoded properly
			Query query = Query.fromQueryParams( params );

			if(query == null && parameters.size() > 0 && parameters.get( 0 ).isId()){
				query = Query.fromUUID( parameters.get( 0 ).getId() );
			}

			if ( query != null ) {
				parameters = ServiceParameter.addParameter( parameters, query );
			}
		}

		return parameters;
	}


	@Path("file")
	public AbstractContextResource getFileResource( @Context UriInfo ui ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.getFileResource" );
		}

		ServiceParameter.addParameter( getServiceParameters(), "assets" );

		PathSegment ps = getFirstPathSegment( "assets" );
		if ( ps != null ) {
			addMatrixParams( getServiceParameters(), ui, ps );
		}

		return getSubResource( AssetsResource.class );
	}


	@Path(RootResource.ENTITY_ID_PATH)
	public AbstractContextResource addIdParameter( @Context UriInfo ui, @PathParam("entityId") PathSegment entityId )
			throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.addIdParameter" );
		}

		UUID itemId = UUID.fromString( entityId.getPath() );

		ServiceParameter.addParameter( getServiceParameters(), itemId );

		addMatrixParams( getServiceParameters(), ui, entityId );

		return getSubResource( ServiceResource.class );
	}


	@Path("{itemName}")
	public AbstractContextResource addNameParameter( @Context UriInfo ui, @PathParam("itemName") PathSegment itemName )
			throws Exception {
		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.addNameParameter" );
			logger.trace( "Current segment is {}", itemName.getPath() );
		}


		if ( itemName.getPath().startsWith( "{" ) ) {
			Query query = Query.fromJsonString( itemName.getPath() );
			if ( query != null ) {
				ServiceParameter.addParameter( getServiceParameters(), query );
			}
		}
		else {
			ServiceParameter.addParameter( getServiceParameters(), itemName.getPath() );
		}

		addMatrixParams( getServiceParameters(), ui, itemName );

		return getSubResource( ServiceResource.class );
	}


	public ServiceResults executeServiceGetRequestForSettings(UriInfo ui, ApiResponse response, ServiceAction action,
			ServicePayload payload) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeServiceRequest" );
		}


		boolean tree = "true".equalsIgnoreCase( ui.getQueryParameters().getFirst( "tree" ) );

		String connectionQueryParm = ui.getQueryParameters().getFirst("connections");
		boolean returnInboundConnections = true;
		boolean returnOutboundConnections = true;

		addQueryParams( getServiceParameters(), ui );

		ServiceRequest r = services.newRequest( action, tree, getServiceParameters(), payload,
				returnInboundConnections, returnOutboundConnections );

		response.setServiceRequest( r );


		AbstractCollectionService abstractCollectionService = new AbstractCollectionService();

		// abstractCollectionService
		ServiceResults results = abstractCollectionService.getCollectionSettings( r );

		//        ServiceResults results = r.execute();
		if ( results != null ) {
			if ( results.hasData() ) {
				response.setData( results.getData() );
			}
			if ( results.getServiceMetadata() != null ) {
				response.setMetadata( results.getServiceMetadata() );
			}
			Query query = r.getLastQuery();
			if ( query != null ) {
				if ( query.hasSelectSubjects() ) {
					response.setList( QueryUtils.getSelectionResults( query, results ) );
					response.setCount( response.getList().size() );
					response.setNext( results.getNextResult() );
					response.setPath( results.getPath() );
					return results;
				}
			}

			response.setResults( results );
		}

		httpServletRequest.setAttribute( "applicationId", services.getApplicationId() );

		return results;
	}

	public ServiceResults executeServicePostRequestForSettings(UriInfo ui, ApiResponse response, ServiceAction action,
			ServicePayload payload) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeServiceRequest" );
		}


		boolean tree = "true".equalsIgnoreCase( ui.getQueryParameters().getFirst( "tree" ) );

		String connectionQueryParm = ui.getQueryParameters().getFirst("connections");
		boolean returnInboundConnections = true;
		boolean returnOutboundConnections = true;

		addQueryParams( getServiceParameters(), ui );

		ServiceRequest r = services.newRequest( action, tree, getServiceParameters(), payload,
				returnInboundConnections, returnOutboundConnections );

		response.setServiceRequest( r );


		AbstractCollectionService abstractCollectionService = new AbstractCollectionService();

		ServiceResults results = abstractCollectionService.postCollectionSettings( r );

		//        ServiceResults results = r.execute();
		if ( results != null ) {
			if ( results.hasData() ) {
				response.setData( results.getData() );
			}
			if ( results.getServiceMetadata() != null ) {
				response.setMetadata( results.getServiceMetadata() );
			}
			Query query = r.getLastQuery();
			if ( query != null ) {
				if ( query.hasSelectSubjects() ) {
					response.setList( QueryUtils.getSelectionResults( query, results ) );
					response.setCount( response.getList().size() );
					response.setNext( results.getNextResult() );
					response.setPath( results.getPath() );
					return results;
				}
			}

			response.setResults( results );
		}

		httpServletRequest.setAttribute( "applicationId", services.getApplicationId() );

		return results;


	}


	public ServiceResults executeServiceRequest( UriInfo ui, ApiResponse response, ServiceAction action,
			ServicePayload payload ) throws Exception {
		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeServiceRequest" );
		}


		boolean tree = "true".equalsIgnoreCase( ui.getQueryParameters().getFirst( "tree" ) );

		String connectionQueryParm = ui.getQueryParameters().getFirst("connections");
		boolean returnInboundConnections = true;
		boolean returnOutboundConnections = true;

		// connection info can be blocked only for GETs
		if (action == ServiceAction.GET) {
			if ("none".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = false;
				returnOutboundConnections = false;
			} else if ("in".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = true;
				returnOutboundConnections = false;
			} else if ("out".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = false;
				returnOutboundConnections = true;
			} else if ("all".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = true;
				returnOutboundConnections = true;
			} else {
				if (connectionQueryParm != null) {
					// unrecognized parameter
					logger.error(String.format(
							"Invalid connections query parameter=%s, ignoring.", connectionQueryParm));
				}
				// use the default query parameter functionality
				OrganizationConfig orgConfig =
						management.getOrganizationConfigForApplication(services.getApplicationId());
				String defaultConnectionQueryParm =
						orgConfig.getProperty(OrganizationConfigProps.ORGPROPERTIES_DEFAULT_CONNECTION_PARAM);
				returnInboundConnections =
						(defaultConnectionQueryParm.equals("in")) || (defaultConnectionQueryParm.equals("all"));
				returnOutboundConnections =
						(defaultConnectionQueryParm.equals("out")) || (defaultConnectionQueryParm.equals("all"));
			}
		}

		boolean collectionGet = false;
		if ( action == ServiceAction.GET ) {
			collectionGet = getServiceParameters().size() == 1;
		}

		List<ServiceParameter> serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ;
		
		ServiceRequest r = null ;
		ServiceResults results = null ;
		boolean applevel = false ;
		ServicePayload appPayload = null ;
		String version = null ;
		Object extendedParam = null;
		
//		if(action != ServiceAction.DELETE )
		{
//			addQueryParams( serviceParam, ui );
			boolean checkServiceParam = exitsInServiceParameter( serviceParam , "users" ) ;
			if( exitsInServiceParameter( serviceParam , "users" ) && !exitsInServiceParameter( serviceParam , "permissions" ) ) {
				//
				r = getServiceRequestForParams(ui, action, tree, serviceParam.size() >1 ? serviceParam.subList(0, 1) :serviceParam, 
						payload, returnInboundConnections, returnOutboundConnections, false, false);
				results = executeNewRequest( response, r);

				System.out.println(results.getId()+"user-entity-store"+"----------"+results.getObject());
				if( payload != null && results.getId() != null ) {
					payload.setProperty( "uuid", results.getId() );
				}
			} 
			else {

				checkServiceParam = exitsInServiceParameter( serviceParam , "permissions" ) ;
				
				if( checkServiceParam ) {
					//
					r = getServiceRequestForParams(ui, action, tree, serviceParam, payload, 
							returnInboundConnections, returnOutboundConnections, false, false);
					results = executeNewRequest(response, r);
					System.out.println("entity-store"+"----------"+results.getObject());
				} 
				else 
				{
					//Only taking the entity name 
					if( !serviceParam.isEmpty()) {
						applevel = true ;

						serviceParam = serviceParam.subList(0, 1);
						appPayload =  getAppEntityPayLoad(ServiceParameter.firstParameter(serviceParam).getName(),ServiceAction.GET);

						r = getServiceRequestForParams(ui, ServiceAction.GET, tree, serviceParam, appPayload, 
								returnInboundConnections, returnOutboundConnections, false, false);
						results =  executeNewRequest(response, r);

						System.out.println("entity-store1"+"----------"+results.getObject());
						
						if(!results.isEmpty()) {
							if(action == ServiceAction.DELETE)
							{
//								serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
//								serviceParam = serviceParam.subList(0, 1);
//								appPayload =  getAppEntityPayLoad(ServiceParameter.firstParameter(serviceParam).getName(),action);
//
//								r = getServiceRequestForParams(ui, ServiceAction.PUT, tree, serviceParam, appPayload, 
//										returnInboundConnections, returnOutboundConnections, false, false);
//								results =  executeNewRequest(response, r);
							}
						}
						else
						{
							if(action == ServiceAction.DELETE) {
								
								throw new Exception("No Allowed "+action+" for Entity "+new ArrayList<ServiceParameter>( getServiceParameters() )) ;
							}
							else if(action == ServiceAction.POST || action == ServiceAction.PUT)
							{
								serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
								serviceParam = serviceParam.subList(0, 1);
								appPayload =  getAppEntityPayLoad(ServiceParameter.firstParameter(serviceParam).getName(),action);

								r = getServiceRequestForParams(ui, ServiceAction.POST, tree, serviceParam, appPayload, 
										returnInboundConnections, returnOutboundConnections, false, false);
								results =  executeNewRequest(response, r);
							}
							
						}
						
						
						System.out.println("entity-store2"+"----------"+results.getObject());
						
						version = results.getEntity().getProperty("version").toString();
						extendedParam = results.getEntity().getProperty(version);
						
					}

					
				}
			}
		} 

		/*
		 * Logic to redirect to org level app space for entities
		 */
		System.out.println("oooooooooooooooo"+extendedParam);
		List<String> find = (List<String>)extendedParam;//find.add("expiry");find.add("code");
		System.out.println("oooooooooooooooo"+find);
		
		if( applevel && find.size()>0) 
		{
			/*
			 * getting existing details on the the entity
			 */
			//Checking if entity exists 
			serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
			r = getServiceRequestForParams(ui, ServiceAction.GET, tree, serviceParam, payload,
					returnInboundConnections, returnOutboundConnections, true,false);
			results = executeNewRequest(response, r);
			
			if(!results.isEmpty() && action == ServiceAction.POST) {
				throw new Exception("No Allowed "+action+" for Entity "+new ArrayList<ServiceParameter>( getServiceParameters() )) ;
			}
			
			System.out.println("entity-store3"+"----------"+results.getObject());
			
			//
			if(action != ServiceAction.DELETE && action != ServiceAction.GET) {

				boolean newEntity = false ;

				if(results.isEmpty()) {
					newEntity = true ;
				}

				Stack<Object> payLoadSplit = new Stack<Object>();

				//Hard coded value has to be changed
				Stack<LinkedHashMap<Object,Object>> appMapStack = new Stack<LinkedHashMap<Object,Object>>();
				
				//
				String applicationName = services.getApplication().getApplicationName() ;

				ServicePayload finalPayload = getFinalPayLoad(payload, version, newEntity, payLoadSplit, appMapStack, find, applicationName) ;

				//
				if( action == ServiceAction.POST ) {
					//
					serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
					r = getServiceRequestForParams(ui, action, tree, serviceParam, finalPayload,
							returnInboundConnections, returnOutboundConnections, true, false);
					results = executeNewRequest(response, r);
					
				}
				else if( action == ServiceAction.PUT  && !results.isEmpty()) {

					Set<String> appList = null ;

					for(int i=0; i < appMapStack.size() ; i++) {
						Object obj = appMapStack.get(i).get(applicationName);

						if(obj!= null ) {
							if(obj instanceof List){
								for(Object object : (List) obj) {
									if(object!= null && object instanceof Map) {
										List<Entity> l = results.getEntities();
										for(Entity entity : l) {
											Object  o =  entity.getProperty(applicationName);
											getfinalPayloadToUpdate(o, (LinkedHashMap) object, applicationName);
											//
											if(entity.getProperty("applications")!=null) {
												appList = (Set<String>) entity.getProperty("applications");
												appList.add(applicationName);
											}
										}
									}
								}
							}

						}
						if(appList!=null) {
							appMapStack.get(i).put("applications", appList);
						}

					}
					finalPayload = ServicePayload.jsonPayload(appMapStack);

					System.out.println("appMapStack!!!!!!!!!"+appMapStack);
					//				int i = 1/0 ;		
					//
					serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
					r = getServiceRequestForParams(ui, action, tree, serviceParam, finalPayload,
							returnInboundConnections, returnOutboundConnections, true, false);
					results = executeNewRequest(response, r);
				}
			}
			else if(action != ServiceAction.GET)
			{
				if(!results.isEmpty()) {
					for(Entity entity : results.getEntities()) {
						Set<String> appSet = null ;

						if(entity.getProperty("applications") != null) {
							appSet = (Set<String>)entity.getProperty("applications");
							
							if(appSet.size()>1)
							{
								String applicationName = services.getApplication().getApplicationName() ;
								Object pay =  getPayLaadForDelete(entity, appSet, applicationName);
								ServicePayload finalPayload = ServicePayload.jsonPayload(pay);
								System.out.println("deleted-------!!!!!"+finalPayload);
//								int a = 1/0 ;
								serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
								r = getServiceRequestForParams(ui, ServiceAction.PUT, tree, serviceParam, finalPayload,
										returnInboundConnections, returnOutboundConnections, true, false);
								results = executeNewRequest(response, r);
							}
							else 
							{
//								int a = 1/0 ;
								//
								serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
								r = getServiceRequestForParams(ui, action, tree, serviceParam, payload,
										returnInboundConnections, returnOutboundConnections, true,true);
								results = executeNewRequest(response, r);
							}
						}
					}
				}
			}
		}
		else
		{
			serviceParam = new ArrayList<ServiceParameter>( getServiceParameters() ) ; 
			r = getServiceRequestForParams(ui, action, tree, serviceParam, payload,
					returnInboundConnections, returnOutboundConnections, true, true);
			results = executeNewRequest(response, r);
		}
		System.out.println("org-app"+"----------"+results.getObject());
		if ( results != null ) {
			if ( results.hasData() ) {
				response.setData( results.getData() );
			}
			if ( results.getServiceMetadata() != null ) {
				response.setMetadata( results.getServiceMetadata() );
			}
			Query query = r.getLastQuery();
			if ( query != null ) {
				if ( query.hasSelectSubjects() ) {
					response.setList( QueryUtils.getSelectionResults( query, results ) );
					response.setCount( response.getList().size() );
					response.setNext( results.getNextResult() );
					response.setPath( results.getPath() );
					return results;
				}
			}
			if ( collectionGet ) {
				response.setCount( results.size() );
			}

			response.setResults( results );
		}

		httpServletRequest.setAttribute( "applicationId", services.getApplicationId() );

		return results;
	}


	@CheckPermissionsForPath
	@GET
	@Produces({MediaType.APPLICATION_JSON, MediaType.TEXT_HTML, "application/javascript"})
	@JSONP
	public ApiResponse executeGet( @Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback )
					throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeGet" );
		}

		ApiResponse response = createApiResponse();

		response.setAction( "get" );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );

		executeServiceRequest( ui, response, ServiceAction.GET, null );

		return response;
	}
	
	@SuppressWarnings({ "unchecked" })
	public ServicePayload getPayload( Object json ) {
		ServicePayload payload = null;
		json = JsonUtils.normalizeJsonTree( json );
		if ( json instanceof Map ) {
			Map<String, Object> jsonMap = ( Map<String, Object> ) json;
			payload = ServicePayload.payload( jsonMap );
		}
		else if ( json instanceof List ) {
			List<?> jsonList = ( List<?> ) json;
			if ( jsonList.size() > 0 ) {
				if ( jsonList.get( 0 ) instanceof UUID ) {
					payload = ServicePayload.idListPayload( ( List<UUID> ) json );
				}
				else if ( jsonList.get( 0 ) instanceof Map ) {
					payload = ServicePayload.batchPayload( ( List<Map<String, Object>> ) jsonList );
				}
			}
		}
		if ( payload == null ) {
			payload = new ServicePayload();
		}
		return payload;
	}




	/**
	 * Necessary to work around inexplicable problems with EntityHolder.
	 * See above.
	 */
	public ApiResponse executePostWithObject( @Context UriInfo ui, Object json,
			@QueryParam("callback") @DefaultValue("callback") String callback ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executePostWithMap" );
		}

		ApiResponse response = createApiResponse();


		response.setAction( "post" );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );

		ServicePayload payload = getPayload( json );

		executeServiceRequest( ui, response, ServiceAction.POST, payload );

		return response;
	}


	/**
	 * Necessary to work around inexplicable problems with EntityHolder.
	 * See above.
	 */
	public ApiResponse executePutWithMap( @Context UriInfo ui, Map<String, Object> json,
			@QueryParam("callback") @DefaultValue("callback") String callback ) throws Exception {

		ApiResponse response = createApiResponse();
		response.setAction( "put" );

		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );

		ServicePayload payload = getPayload( json );

		executeServiceRequest( ui, response, ServiceAction.PUT, payload );

		return response;
	}


	@CheckPermissionsForPath
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	public ApiResponse executePost( @Context UriInfo ui, String body,
			@QueryParam("callback") @DefaultValue("callback") String callback ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executePost: body = {}", body );
		}

		Object json;
		if ( StringUtils.isEmpty( body ) ) {
			json = null;
		} else {
			json = readJsonToObject( body );
		}

		ApiResponse response = createApiResponse();


		response.setAction( "post" );

		if(services != null) {
			response.setApplication( services.getApplication() );
		}

		response.setParams( ui.getQueryParameters() );

		ServicePayload payload = getPayload( json );

		executeServiceRequest( ui, response, ServiceAction.POST, payload );

		return response;
	}



	@CheckPermissionsForPath
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	public ApiResponse executePut( @Context UriInfo ui, String body,
			@QueryParam("callback") @DefaultValue("callback") String callback )
					throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executePut" );
		}

		ObjectMapper mapper = new ObjectMapper();
		Map<String, Object> json = mapper.readValue( body, mapTypeReference );

		return executePutWithMap(ui, json, callback);
	}


	@CheckPermissionsForPath
	@DELETE
	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	public ApiResponse executeDelete(
			@Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback,
			@QueryParam("app_delete_confirm") String confirmAppDelete )
					throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeDelete" );
		}

		ApiResponse response = createApiResponse();
		response.setAction( "delete" );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );

		ServiceResults sr = executeServiceRequest( ui, response, ServiceAction.DELETE, null );

		// if we deleted an entity (and not a connection or collection) then
		// we may need to clean up binary asset data associated with that entity

		if (    !sr.getResultsType().equals( ServiceResults.Type.CONNECTION )
				&& !sr.getResultsType().equals( ServiceResults.Type.COLLECTION )) {

			for ( Entity entity : sr.getEntities() ) {
				if ( entity.getProperty( AssetUtils.FILE_METADATA ) != null ) {
					try {
						binaryStore.delete( services.getApplicationId(), entity );
					}catch(AwsPropertiesNotFoundException apnfe){
						logger.error( "Amazon Property needed for this operation not found",apnfe );
						response.setError( "500","Amazon Property needed for this operation not found",apnfe );
					}
				}
			}
		}

		return response;
	}

	//    TODO Temporarily removed until we test further
	//    @Produces("text/csv")
	//    @GET
	//    @RequireApplicationAccess
	//    @Consumes("text/csv")
	//    public String executeGetCsv(@Context UriInfo ui,
	//            @QueryParam("callback") @DefaultValue("callback") String callback)
	//                    throws Exception {
	//        ui.getQueryParameters().putSingle("pad", "true");
	//        JSONWithPadding jsonp = executeGet(ui, callback);
	//
	//        StringBuilder builder = new StringBuilder();
	//        if ((jsonp != null) && (jsonp.getJsonSource() instanceof ApiResponse)) {
	//            ApiResponse apiResponse = (ApiResponse) jsonp.getJsonSource();
	//            if ((apiResponse.getCounters() != null)
	//                    && (apiResponse.getCounters().size() > 0)) {
	//                List<AggregateCounterSet> counters = apiResponse.getCounters();
	//                int size = counters.get(0).getValues().size();
	//                List<AggregateCounter> firstCounterList = counters.get(0)
	//                        .getValues();
	//                if (size > 0) {
	//                    builder.append("timestamp");
	//                    for (AggregateCounterSet counterSet : counters) {
	//                        builder.append(",");
	//                        builder.append(counterSet.getName());
	//                    }
	//                    builder.append("\n");
	//                    SimpleDateFormat formatter = new SimpleDateFormat(
	//                            "yyyy-MM-dd HH:mm:ss.SSS");
	//                    for (int i = 0; i < size; i++) {
	//                        // yyyy-mm-dd hh:mm:ss.000
	//                        builder.append(formatter.format(new Date(
	//                                firstCounterList.get(i).getTimestamp())));
	//                        for (AggregateCounterSet counterSet : counters) {
	//                            List<AggregateCounter> counterList = counterSet
	//                                    .getValues();
	//                            builder.append(",");
	//                            builder.append(counterList.get(i).getValue());
	//                        }
	//                        builder.append("\n");
	//                    }
	//                }
	//            } else if ((apiResponse.getEntities() != null)
	//                    && (apiResponse.getEntities().size() > 0)) {
	//                for (Entity entity : apiResponse.getEntities()) {
	//                    builder.append(entity.getUuid());
	//                    builder.append(",");
	//                    builder.append(entity.getType());
	//                    builder.append(",");
	//                    builder.append(mapToJsonString(entity));
	//                }
	//
	//            }
	//        }
	//        return builder.toString();
	//    }


	public static String wrapWithCallback( AccessInfo accessInfo, String callback ) {
		return wrapWithCallback( JsonUtils.mapToJsonString( accessInfo ), callback );
	}


	public static String wrapWithCallback( String json, String callback ) {
		if ( StringUtils.isNotBlank( callback ) ) {
			json = callback + "(" + json + ")";
		}
		return json;
	}


	public static MediaType jsonMediaType( String callback ) {
		return StringUtils.isNotBlank( callback ) ? new MediaType( "application", "javascript" ) : APPLICATION_JSON_TYPE;
	}


	/** ************** the following is file attachment (Asset) support ********************* */

	@CheckPermissionsForPath
	@POST
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	public ApiResponse executeMultiPartPost( @Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback,
			FormDataMultiPart multiPart ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeMultiPartPost" );
		}
		return executeMultiPart( ui, callback, multiPart, ServiceAction.POST );
	}


	@CheckPermissionsForPath
	@PUT
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	public ApiResponse executeMultiPartPut( @Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback,
			FormDataMultiPart multiPart ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeMultiPartPut" );
		}
		return executeMultiPart( ui, callback, multiPart, ServiceAction.PUT );
	}


	@JSONP
	@Produces({MediaType.APPLICATION_JSON, "application/javascript"})
	private ApiResponse executeMultiPart( UriInfo ui, String callback, FormDataMultiPart multiPart,
			ServiceAction serviceAction ) throws Exception {

		//needed for testing
		if(properties.getProperty( PROPERTIES_USERGRID_BINARY_UPLOADER ).equals( "local" )){
			this.binaryStore = localFileBinaryStore;
		}
		else{
			this.binaryStore = awsSdkS3BinaryStore;
		}

		// collect form data values
		List<BodyPart> bodyParts = multiPart.getBodyParts();
		HashMap<String, Object> data = new HashMap<>();
		for ( BodyPart bp : bodyParts ) {
			FormDataBodyPart bodyPart = ( FormDataBodyPart ) bp;
			if ( bodyPart.getMediaType().equals( MediaType.TEXT_PLAIN_TYPE ) ) {
				data.put( bodyPart.getName(), bodyPart.getValue() );
			}
			else {
				if (logger.isTraceEnabled()) {
					logger.trace("skipping bodyPart {} of media type {}", bodyPart.getName(), bodyPart.getMediaType());
				}
			}
		}

		FormDataBodyPart fileBodyPart = multiPart.getField( FILE_FIELD_NAME );

		data.put( AssetUtils.FILE_METADATA, new HashMap() );

		// process entity
		ApiResponse response = createApiResponse();
		response.setAction( serviceAction.name().toLowerCase() );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );

		//Updates entity with fields that are in text/plain as per loop above
		if(data.get( FILE_FIELD_NAME )==null){
			data.put( FILE_FIELD_NAME,null );
		}
		ServicePayload payload = getPayload( data );
		ServiceResults serviceResults = executeServiceRequest( ui, response, serviceAction, payload );

		// process file part
		if ( fileBodyPart != null ) {
			InputStream fileInput = ( (BodyPartEntity) fileBodyPart.getEntity() ).getInputStream();
			if ( fileInput != null ) {
				Entity entity = serviceResults.getEntity();
				EntityManager em = emf.getEntityManager( getApplicationId() );
				try {
					binaryStore.write( getApplicationId(), entity, fileInput );
				}
				catch ( AwsPropertiesNotFoundException apnfe){
					logger.error( "Amazon Property needed for this operation not found",apnfe );
					response.setError( "500","Amazon Property needed for this operation not found",apnfe );
				}
				catch ( RuntimeException re){
					logger.error(re.getMessage());
					response.setError( "500", re );
				}
				//em.update( entity );
				entity = serviceResults.getEntity();
				serviceResults.setEntity( entity );
			}
		}

		return response;
	}


	@CheckPermissionsForPath
	@PUT
	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	public Response uploadDataStreamPut( @Context UriInfo ui, InputStream uploadedInputStream ) throws Exception {
		return uploadDataStream( ui, uploadedInputStream );
	}


	@CheckPermissionsForPath
	@POST
	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	public Response uploadDataStream( @Context UriInfo ui, InputStream uploadedInputStream ) throws Exception {

		//needed for testing
		if(properties.getProperty( PROPERTIES_USERGRID_BINARY_UPLOADER ).equals( "local" )){
			this.binaryStore = localFileBinaryStore;
		}
		else{
			this.binaryStore = awsSdkS3BinaryStore;
		}

		ApiResponse response = createApiResponse();
		response.setAction( "get" );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );
		ServiceResults serviceResults = executeServiceRequest( ui, response, ServiceAction.GET, null );

		Entity entity = serviceResults.getEntity();
		try {
			binaryStore.write( getApplicationId(), entity, uploadedInputStream );
		}catch(AwsPropertiesNotFoundException apnfe){
			logger.error( "Amazon Property needed for this operation not found",apnfe );
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
		}catch ( RuntimeException re ){
			logger.error(re.getMessage());
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
		}

		EntityManager em = emf.getEntityManager( getApplicationId() );
		em.update( entity );
		return Response.status( 200 ).build();
	}

	@CheckPermissionsForPath
	@GET
	@Produces(MediaType.WILDCARD)
	public Response executeStreamGet( @Context UriInfo ui, @PathParam("entityId") PathSegment entityId,
			@HeaderParam("range") String rangeHeader,
			@HeaderParam("if-modified-since") String modifiedSince ) throws Exception {

		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeStreamGet" );
		}

		//Needed for testing
		if(properties.getProperty( PROPERTIES_USERGRID_BINARY_UPLOADER ).equals( "local" )){
			this.binaryStore = localFileBinaryStore;
		}
		else{
			this.binaryStore = awsSdkS3BinaryStore;
		}

		ApiResponse response = createApiResponse();
		response.setAction( "get" );
		response.setApplication( services.getApplication() );
		response.setParams( ui.getQueryParameters() );
		ServiceResults serviceResults = executeServiceRequest( ui, response, ServiceAction.GET, null );
		Entity entity = serviceResults.getEntity();

		if(logger.isTraceEnabled()){
			logger.trace( "In ServiceResource.executeStreamGet with id: {}, range: {}, modifiedSince: {}",
					entityId, rangeHeader, modifiedSince );
		}

		Map<String, Object> fileMetadata = AssetUtils.getFileMetadata( entity );

		// return a 302 if not modified
		Date modified = AssetUtils.fromIfModifiedSince( modifiedSince );
		if ( modified != null ) {
			Long lastModified = ( Long ) fileMetadata.get( AssetUtils.LAST_MODIFIED );
			if ( lastModified - modified.getTime() < 0 ) {
				return Response.status( Response.Status.NOT_MODIFIED ).build();
			}
		}

		boolean range = StringUtils.isNotBlank( rangeHeader );
		long start = 0, end = 0, contentLength = 0;
		InputStream inputStream;

		if ( range ) { // honor range request, calculate start & end

			String rangeValue = rangeHeader.trim().substring( "bytes=".length() );
			contentLength = ( Long ) fileMetadata.get( AssetUtils.CONTENT_LENGTH );
			end = contentLength - 1;
			if ( rangeValue.startsWith( "-" ) ) {
				start = contentLength - 1 - Long.parseLong( rangeValue.substring( "-".length() ) );
			}
			else {
				String[] startEnd = rangeValue.split( "-" );
				long parsedStart = Long.parseLong( startEnd[0] );
				if ( parsedStart > start && parsedStart < end ) {
					start = parsedStart;
				}
				if ( startEnd.length > 1 ) {
					long parsedEnd = Long.parseLong( startEnd[1] );
					if ( parsedEnd > start && parsedEnd < end ) {
						end = parsedEnd;
					}
				}
			}
			try {
				inputStream = binaryStore.read( getApplicationId(), entity, start, end - start );
			}catch(AwsPropertiesNotFoundException apnfe){
				logger.error( "Amazon Property needed for this operation not found",apnfe );
				return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
			}catch(RuntimeException re){
				logger.error(re.getMessage());
				return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
			}
		}
		else { // no range
			try {
				inputStream = binaryStore.read( getApplicationId(), entity );
			}catch(AwsPropertiesNotFoundException apnfe){
				logger.error( "Amazon Property needed for this operation not found",apnfe );
				return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
			}
			catch(AmazonServiceException ase){

				if( ase.getStatusCode() > 499 ){
					logger.error(ase.getMessage());
				}else if(logger.isDebugEnabled()){
					logger.debug(ase.getMessage());
				}
				return Response.status(ase.getStatusCode()).build();
			}
			catch(RuntimeException re){
				logger.error(re.getMessage());
				return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
			}
		}

		// return 404 if not found
		if ( inputStream == null ) {
			return Response.status( Response.Status.NOT_FOUND ).build();
		}

		Long lastModified = ( Long ) fileMetadata.get( AssetUtils.LAST_MODIFIED );
		Response.ResponseBuilder responseBuilder =
				Response.ok( inputStream ).type( ( String ) fileMetadata.get( AssetUtils.CONTENT_TYPE ) )
				.lastModified( new Date( lastModified ) );

		if ( fileMetadata.get( AssetUtils.E_TAG ) != null ) {
			responseBuilder.tag( ( String ) fileMetadata.get( AssetUtils.E_TAG ) );
		}

		if ( range ) {
			responseBuilder.header( "Content-Range", "bytes " + start + "-" + end + "/" + contentLength );
		}

		return responseBuilder.build();
	}

	/*
	 * --Nupin--start--
	 */
	public ServiceResults executeServiceRequestDB( UriInfo ui, ApiResponse response, ServiceAction action,
			ServicePayload payload ) throws Exception {
		if(logger.isTraceEnabled()){
			logger.trace( "ServiceResource.executeServiceRequest" );
		}


		boolean tree = "true".equalsIgnoreCase( ui.getQueryParameters().getFirst( "tree" ) );

		String connectionQueryParm = ui.getQueryParameters().getFirst("connections");
		boolean returnInboundConnections = true;
		boolean returnOutboundConnections = true;

		// connection info can be blocked only for GETs
		if (action == ServiceAction.GET) {
			if ("none".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = false;
				returnOutboundConnections = false;
			} else if ("in".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = true;
				returnOutboundConnections = false;
			} else if ("out".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = false;
				returnOutboundConnections = true;
			} else if ("all".equalsIgnoreCase(connectionQueryParm)) {
				returnInboundConnections = true;
				returnOutboundConnections = true;
			} else {
				if (connectionQueryParm != null) {
					// unrecognized parameter
					logger.error(String.format(
							"Invalid connections query parameter=%s, ignoring.", connectionQueryParm));
				}
				// use the default query parameter functionality
				OrganizationConfig orgConfig =
						management.getOrganizationConfigForApplication(services.getApplicationId());
				String defaultConnectionQueryParm =
						orgConfig.getProperty(OrganizationConfigProps.ORGPROPERTIES_DEFAULT_CONNECTION_PARAM);
				returnInboundConnections =
						(defaultConnectionQueryParm.equals("in")) || (defaultConnectionQueryParm.equals("all"));
				returnOutboundConnections =
						(defaultConnectionQueryParm.equals("out")) || (defaultConnectionQueryParm.equals("all"));
			}
		}

		boolean collectionGet = false;
		if ( action == ServiceAction.GET ) {
			collectionGet = getServiceParameters().size() == 1;
		}
		addQueryParams( getServiceParameters(), ui );
		ServiceRequest r = services.newRequest( action, tree, getServiceParameters(), payload,
				returnInboundConnections, returnOutboundConnections );//need to check appid inside debugging
		response.setServiceRequest( r );
		ServiceResults results = r.executeDB();
		if ( results != null ) {
			if ( results.hasData() ) {
				response.setData( results.getData() );
			}
			if ( results.getServiceMetadata() != null ) {
				response.setMetadata( results.getServiceMetadata() );
			}
			Query query = r.getLastQuery();
			if ( query != null ) {
				if ( query.hasSelectSubjects() ) {
					response.setList( QueryUtils.getSelectionResults( query, results ) );
					response.setCount( response.getList().size() );
					response.setNext( results.getNextResult() );
					response.setPath( results.getPath() );
					return results;
				}
			}
			if ( collectionGet ) {
				response.setCount( results.size() );
			}

			response.setResults( results );
		}

		httpServletRequest.setAttribute( "applicationId", services.getApplicationId() );

		return results;
	}

	private ServicePayload getAppEntityPayLoad(String serviceName, ServiceAction action) throws Exception {    
		if(action == ServiceAction.DELETE) {
			return ServicePayload.jsonPayload("{\"status\":\"deleted\"}");
		}
		else
		{
			return  ServicePayload.jsonPayload(readJsonToObject("[{\"name\":\""+pluralize(serviceName)+"\",\"type\":\""+
					(serviceName)+getVersionDiffParams()+",\"status\":\"deleted\"}]")) ;   	
		}
	}

	//Hardcoded values has to be removed
	private String getVersionDiffParams() {
		return "\",\"version\":\"3.1.2\",\"3.1.2\":[\"code\",\"expiry\"]";
	}



	@SuppressWarnings("unchecked")
	private Stack<Object> processFinalPayLoad(Object object, String applicationName, List<String> find, Stack<Object> payLoadSplit, 
			Stack<LinkedHashMap<Object,Object>> appMapStack, String version, boolean isFirstMap, boolean newEntity) {

		if(object instanceof Map)
		{
			LinkedHashMap<Object,Object> diffMap = new LinkedHashMap<Object,Object>();
			
			LinkedHashMap<Object,Object> payLoadObject = new LinkedHashMap<Object,Object>();
			
			if(isFirstMap) {
				LinkedHashMap<Object,Object> appMap = new LinkedHashMap<Object,Object>();
				appMap.put(applicationName, null);
				//supported applications
//				List<String> appList = new ArrayList<String>();appList.add(applicationName);
//				appMap.put("applications", appList);
				if(newEntity) {
					appMap.put("version", version);
					appMap.put("source",applicationName);
					appMap.put("status","active");
					newEntity = false ;
				}
				appMapStack.push(appMap);
				payLoadObject = new LinkedHashMap<Object,Object>();
				payLoadObject = appMap ;
				diffMap = new LinkedHashMap<Object,Object>();
				diffMap.put("version", version);
				diffMap.put("status","active"); 
				
				isFirstMap = false ;
			}
		
			for(Object key : ((Map)object).keySet())
			{
				if(find.contains(key.toString()))
				{
					diffMap.put(key, ((Map)object).get(key));
				}
				else
				{
					processFinalPayLoad(((Map)object).get(key), applicationName, find, payLoadSplit, appMapStack, version, isFirstMap, newEntity);
					payLoadObject.put(key, payLoadSplit.pop());
					if((payLoadSplit.peek() instanceof List) || (payLoadSplit.peek() instanceof Map))
					{
						diffMap.put(key, payLoadSplit.pop());	
					}
					else 
					{
						payLoadSplit.pop();
					}
				}
			}
			payLoadSplit.push(payLoadObject);
			payLoadSplit.push(diffMap);
			return payLoadSplit ;
		}
		else if(object instanceof List) 
		{
			List<Object> arr = new ArrayList<Object>();
			
			List<Object> payLoadArray = new ArrayList<Object>();			
			
			for(Object row : (List)object ) 
			{
				processFinalPayLoad(row, applicationName, find, payLoadSplit, appMapStack, version, isFirstMap, newEntity);
				
				arr.add(payLoadSplit.pop());
				payLoadArray.add(payLoadSplit.pop());
			}
			payLoadSplit.push(arr);payLoadSplit.push(payLoadArray);
			return payLoadSplit;
		}
		else
		{	payLoadSplit.push(object);payLoadSplit.push(object);
			return payLoadSplit;
		}
	}

	public List<ServiceParameter> getDBServiceParameters() {

		if ( getServiceResourceParent() != null ) {
			return getServiceResourceParent().getServiceParameters();
		}
		serviceParameters = new ArrayList<>();
		return serviceParameters;
	}

	public boolean exitsInServiceParameter(List<ServiceParameter> serviceParam, String parameterName) {
		for( ServiceParameter sp : serviceParam ) {
			if(sp.getName().equals( parameterName )) {
				return true ;
			}
		}
		return false ;
	}
	
	private ServiceResults executeNewRequest( ApiResponse response, ServiceRequest r) throws Exception {
		
		
		response.setServiceRequest( r );
		return r.execute();
	}

	private ServiceRequest getServiceRequestForParams(UriInfo ui, ServiceAction action, boolean tree, List<ServiceParameter> serviceParam, 
			ServicePayload payload, boolean returnInboundConnections, 
			boolean returnOutboundConnections, boolean orgApp, boolean considerQP) throws Exception {
		ServiceRequest r = null ;
		
		if(!orgApp)
		{
			r = services.newRequest( action, tree, serviceParam, payload,
					returnInboundConnections, returnOutboundConnections );
		}
		else
		{	
			if(considerQP) {
				addQueryParams( serviceParam, ui );
			}
			orgServices = smf.getServiceManager( getOrgSpaceId(getOrganizationName()) );
			r = orgServices.newRequest( action, tree, serviceParam, payload,
					returnInboundConnections, returnOutboundConnections );
		}
		
		return r ;
	}
	
	private ServicePayload getFinalPayLoad(ServicePayload payload, String version, boolean newEntity, Stack<Object> payLoadSplit, 
			Stack<LinkedHashMap<Object,Object>> appMapStack, List<String> find, String applicationName) {
		
		ServicePayload finalPayload = null ;

		if( payload.isBatch() ) {
			payLoadSplit = processFinalPayLoad((payload.getBatchProperties()), applicationName, find, payLoadSplit, appMapStack, version, true, newEntity) ;				
		}
		else 
		{
			payLoadSplit = processFinalPayLoad((payload.getProperties()), applicationName, find , payLoadSplit, appMapStack, version, true, newEntity) ;
		}

		System.out.println("|||--->>>"+payLoadSplit);System.out.println();System.out.println();

		System.out.println("<<<--->>>"+appMapStack);System.out.println();System.out.println();

		Object payload1 = payLoadSplit.pop();
		System.out.println("xxxx"+payload1);
		Object splitPayLoad = payLoadSplit.pop();
		//				appMap.put("slack", val2);
		System.out.println("yyyy"+splitPayLoad);

		if(appMapStack.size()>1) {

			for(int i=0; i < appMapStack.size() ; i++) {
				appMapStack.get(i).put(applicationName, ((List)splitPayLoad).get(i));
				if(newEntity){
					Set<String> appSet = new HashSet<String>();appSet.add(applicationName);
					appMapStack.get(i).put("applications", appSet);
				}
				System.out.println("$$$$"+appMapStack.get(i).get("slack"));

			}
		}
		else {
			List<Object> a = new ArrayList<Object>();a.add(payload1);
			if(splitPayLoad instanceof List) {

				LinkedHashMap<Object,Object> map = appMapStack.get(0) ;
				System.out.println("1####1"+map);
				map.put(applicationName, splitPayLoad);
				System.out.println("2####2"+map);
			}
			else
			{
				System.out.println("3#####3"+appMapStack.get(0).get(applicationName));
				appMapStack.get(0).put(applicationName, a);
			}
		}

		System.out.println("appMapStack########"+appMapStack);
		finalPayload = ServicePayload.jsonPayload(appMapStack);

		System.out.println(finalPayload);

		System.out.println("xxxxxxx"+finalPayload);
		
		return finalPayload ;

	}
	
	private LinkedHashMap getfinalPayloadToUpdate(Object entityObj, LinkedHashMap applicationMap, String applicationName) {


		if(entityObj instanceof Map) {
			for(Object key : ((Map)entityObj).keySet()) {
				if(!applicationMap.containsKey(key)) {
					applicationMap.put(key, ((Map)entityObj).get(key));
				}
			}
			System.out.println("applicationmap1"+applicationMap);
			return applicationMap ;
		}
		else if( entityObj instanceof List ) {
			for(Object o : (List)entityObj) {
				getfinalPayloadToUpdate(o, applicationMap, applicationName);
			}
			return applicationMap;
		}				

		System.out.println("applicationmap3"+applicationMap);
		return applicationMap ;
	}
	
	
	private Object getPayLaadForDelete(Entity entity , Set<String> appSet, String applicationName) {
		LinkedHashMap<Object, Object> payloadMap = new LinkedHashMap<Object, Object>();
		
		payloadMap.put("status", "sibling-deleted");
		
		for(String appName : appSet) {
			
				Object obj = entity.getProperty(appName) ;
				if(applicationName.equals(appName)){
				if( obj !=null )
				{
					if(obj instanceof List){
						for(Object o : (List)obj) {
							Map map = (Map)o ;
							map.put("status", "deleted");
						}
					}
					else {
						Map map = (Map)obj ;
						map.put("status", "deleted");
					}
				}
				payloadMap.put(appName,obj);
			}
			else
			{
				payloadMap.put(appName,obj);
			}
		}
		appSet.remove(applicationName);
		payloadMap.put("applications",appSet);
		
		return payloadMap;
	}
	
	/*
	 * --end--
	 */

}
