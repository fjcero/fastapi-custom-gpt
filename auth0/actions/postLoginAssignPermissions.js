/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  const ManagementClient = require("auth0").ManagementClient;
  const management = new ManagementClient({
    domain: event.secrets.auth0_domain,
    clientId: event.secrets.auth0_clientId,
    clientSecret: event.secrets.auth0_clientSecret,
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
  const permissions = ["read:all", "write:all"];
  await assignPermissions(user_id, permissions);
};
