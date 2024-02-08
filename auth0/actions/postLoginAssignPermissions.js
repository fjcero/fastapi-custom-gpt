/**
 * Handler that will be called during the execution of a PostUserRegistration flow.
 *
 * @param {Event} event - Details about the context and user that has registered.
 * @param {PostUserRegistrationAPI} api - Methods and utilities to help change the behavior after a signup.
 */
exports.onExecutePostUserRegistration = async (event, api) => {
  const ManagementClient = require("auth0").ManagementClient;
  const management = new ManagementClient({
    domain: env.domain,
    clientId: env.clientId,
    clientSecret: env.clientSecret,
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
