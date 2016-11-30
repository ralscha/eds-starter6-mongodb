Ext.define("Starter.model.User",
{
  extend : "Ext.data.Model",
  requires : [ "Ext.data.identifier.Uuid", "Ext.data.proxy.Direct", "Ext.data.validator.Email" ],
  identifier : "uuid",
  fields : [ {
    name : "twoFactorAuth",
    type : "boolean",
    persist : false
  }, {
    name : "id",
    type : "string",
    allowNull : true,
    convert : null
  }, {
    name : "loginName",
    type : "string",
    validators : [ {
      type : "notBlank"
    } ]
  }, {
    name : "lastName",
    type : "string",
    validators : [ {
      type : "notBlank"
    } ]
  }, {
    name : "firstName",
    type : "string",
    validators : [ {
      type : "notBlank"
    } ]
  }, {
    name : "email",
    type : "string",
    validators : [ {
      type : "email"
    }, {
      type : "notBlank"
    } ]
  }, "authorities", {
    name : "locale",
    type : "string",
    validators : [ {
      type : "notBlank"
    } ]
  }, {
    name : "enabled",
    type : "boolean"
  }, {
    name : "failedLogins",
    type : "integer",
    persist : false
  }, {
    name : "lockedOutUntil",
    type : "date",
    dateFormat : "time",
    persist : false
  }, {
    name : "lastAccess",
    type : "date",
    dateFormat : "time",
    persist : false
  } ],
  proxy : {
    type : "direct",
    api : {
      read : "userService.read",
      create : "userService.update",
      update : "userService.update",
      destroy : "userService.destroy"
    },
    reader : {
      rootProperty : "records"
    },
    writer : {
      writeAllFields : true
    }
  }
});