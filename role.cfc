component output="false" {

	variables.fw = '';

	variables.rules = [ 
	 	 {whitelist = "", securelist = "^admin", roles = "admin,superuser", redirect = "securityUser:main", noaccess="/no-access.cfm"}		
		,{whitelist = "", securelist = "^report", roles = "user", redirect = "securityUser:main", noaccess="/no-access.cfm"}		
		,{whitelist="", securelist="^roadshow:main.*", roles="rsadmin,admin,superuser", redirect="securityUser:main", noaccess="roadshow:report"}
		,{whitelist="", securelist="^roadshow:report.*", roles="rsadmin,rsview,admin,superuser", redirect="securityUser:main", noaccess="roadshow:report"}
		,{whitelist="", securelist="^user:*", roles="user,admin,superuser", redirect="securityUser:main", noaccess="public:main.noaccess"}

		,{whitelist="^common:*", securelist = "", roles = ""}
		,{whitelist="^public:*", securelist = "", roles = ""}
		,{whitelist="^securityUser:*", securelist = "", roles = ""}

	];
	
	public any function init( required any fw ) {
    		variables.fw = arguments.fw;
    		return this;
  	}
  
	public any function checkUser(currentAction,sessionStruct,rolekey)  {

	        var loggedin = isstruct(arguments.sessionStruct) 
        		and structkeyexists(arguments.sessionStruct,arguments.rolekey) 
        		and arguments.sessionStruct[arguments.rolekey] neq 'guest' AND arguments.sessionStruct[arguments.rolekey] neq '';
        	var rulesLen = arrayLen(rules);
        	var securearea = true;
        
		for(x=1; x lte rulesLen; x=x+1){
		   	if( rules[x].roles eq "" or isActionInPattern (arguments.currentAction, rules[x].whitelist) )
	      		continue;
	      	if( isActionInPattern (arguments.currentAction, rules[x].securelist) ){
	      		if(!loggedin) {
	      			variables.fw.redirect(rules[x].redirect);
				} else {
					bUserOK = false;
					for(r=1; r lte listLen(arguments.sessionStruct[arguments.rolekey]); r=r+1){
						if (listFindNoCase(rules[x].roles,listGetAt(arguments.sessionStruct[arguments.rolekey],r,',') ) neq 0 ) {
							bUserOK = true;
						}
					}					
					if(!bUserOK) {
						variables.fw.redirect(rules[x].noaccess);
					}
				}
	      	}  		
		}
  	}
  	
	private boolean function isActionInPattern(currentAction, patternList){
		
		for ( var unsecured in ListToArray( patternList ) ) 	{
	        if ( ReFindNoCase( unsecured, currentAction ) != 0)
	        	return true;        
      		}
      		return false;
  	}
	
}
