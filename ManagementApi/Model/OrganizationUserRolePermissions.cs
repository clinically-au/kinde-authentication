/*
 * Kinde Management API
 *
 * Provides endpoints to manage your Kinde Businesses
 *
 * The version of the OpenAPI document: 1
 * Contact: support@kinde.com
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using System.Text;

namespace Clinically.Kinde.Authentication.ManagementApi.Model
{
    /// <summary>
    /// OrganizationUserRolePermissions
    /// </summary>
    [DataContract(Name = "organization_user_role_permissions")]
    public partial class OrganizationUserRolePermissions : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OrganizationUserRolePermissions" /> class.
        /// </summary>
        /// <param name="id">id.</param>
        /// <param name="role">role.</param>
        /// <param name="permissions">permissions.</param>
        public OrganizationUserRolePermissions(string id = default(string), string role = default(string), OrganizationUserRolePermissionsPermissions permissions = default(OrganizationUserRolePermissionsPermissions))
        {
            this.Id = id;
            this.Role = role;
            this.Permissions = permissions;
        }

        /// <summary>
        /// Gets or Sets Id
        /// </summary>
        [DataMember(Name = "id", EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// Gets or Sets Role
        /// </summary>
        [DataMember(Name = "role", EmitDefaultValue = false)]
        public string Role { get; set; }

        /// <summary>
        /// Gets or Sets Permissions
        /// </summary>
        [DataMember(Name = "permissions", EmitDefaultValue = false)]
        public OrganizationUserRolePermissionsPermissions Permissions { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class OrganizationUserRolePermissions {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Role: ").Append(Role).Append("\n");
            sb.Append("  Permissions: ").Append(Permissions).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}