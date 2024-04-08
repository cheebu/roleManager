component output="true" {

	variables.rules = [ 
	 	 {whitelist = "" , securelist = "^admin", roles = "administrator", redirect = "/login.cfm", noaccess="/no-access.cfm"}		
		,{whitelist = "" , securelist = "^report", roles = "4", redirect = "/login.cfm", noaccess="/no-access.cfm"}		
		,{whitelist = "" , securelist = "^sectiona", roles = "2,3,4", redirect = "/login.cfm", noaccess="/no-access.cfm"}
		,{whitelist = "" , securelist = "^sectionb", roles = "3,4", redirect = "/login.cfm", noaccess="/no-access.cfm"}

		,{whitelist = "^public", securelist = "", roles = ""}

	];
	
	public any function init( ) {
    	return this;
  	}
  
	public any function checkUser(currentAction,sessionStruct,rolekey)  {

        var loggedIn = isStruct(arguments.sessionStruct) 
        	and structKeyExists(arguments.sessionStruct,arguments.rolekey) 
        	and arguments.sessionStruct[arguments.rolekey] neq 'guest' 
			AND arguments.sessionStruct[arguments.rolekey] neq '';
        var rulesLen = arrayLen(rules);
        var securearea = true;    	
		
		for(x=1; x lte rulesLen; x++){
		   	if(rules[x].roles eq "" or isActionInPattern (arguments.currentAction, rules[x].whitelist))
	      		continue;
	      	if(isActionInPattern (arguments.currentAction, rules[x].securelist)){
	      		if(!loggedIn) {
	      			location('#rules[x].redirect#','false','301');
				} else {
					bUserOK = false;
					for(r=1; r lte listLen(arguments.sessionStruct[arguments.rolekey]); r++){
						if (listFindNoCase(rules[x].roles,listGetAt(arguments.sessionStruct[arguments.rolekey],r,',') ) neq 0 ) {
							bUserOK = true;
						}
					}					
					if(!bUserOK) {
						location('#rules[x].redirect#','false','301');
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
