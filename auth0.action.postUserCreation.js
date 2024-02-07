/**
 * Handler that will be called during the execution of a PostUserRegistration flow.
 *
 * @param {Event} event - Details about the context and user that has registered.
 * @param {PostUserRegistrationAPI} api - Methods and utilities to help change the behavior after a signup.
 */
exports.onExecutePostUserRegistration = async (event, api) => {
  const ManagementClient = require("auth0").ManagementClient;
  const management = new ManagementClient({
    domain: "dev-exfy5kks8o6zwoko.us.auth0.com",
    clientId: "1PDJJmnNNeH2rTKXEbpAcr5iqiMH0LNC",
    clientSecret:
      "HQmtaWKRMgAzWn5RsD1QyPwe7DvigcypCpxfgDLOZro3zJ6PW_7rGiZe7CZSHhn-",
  });

  const resourceId = "https://fastapi_custom_gpts";

  const assignPermissions = async (id, permissions) => {
    return management.users.assignPermissions(
      { id },
      {
        permissions: permissions.filter(Boolean).map((p) => ({
          permission_name: p,
          resource_server_identifier: resourceId,
        })),
      }
    );
  };

  const user_id = event.user.user_id;
  const permissions = ["all:read", "all:write"];
  await assignPermissions(user_id, permissions);
};
