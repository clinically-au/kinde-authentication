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
    /// AddOrganizationUsersRequestUsersInner
    /// </summary>
    [DataContract(Name = "AddOrganizationUsers_request_users_inner")]
    public partial class AddOrganizationUsersRequestUsersInner : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AddOrganizationUsersRequestUsersInner" /> class.
        /// </summary>
        /// <param name="id">The users id..</param>
        /// <param name="roles">Role keys to assign to the user..</param>
        /// <param name="permissions">Permission keys to assign to the user..</param>
        public AddOrganizationUsersRequestUsersInner(string id = default(string), List<string> roles = default(List<string>), List<string> permissions = default(List<string>))
        {
            this.Id = id;
            this.Roles = roles;
            this.Permissions = permissions;
        }

        /// <summary>
        /// The users id.
        /// </summary>
        /// <value>The users id.</value>
        [DataMember(Name = "id", EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// Role keys to assign to the user.
        /// </summary>
        /// <value>Role keys to assign to the user.</value>
        [DataMember(Name = "roles", EmitDefaultValue = false)]
        public List<string> Roles { get; set; }

        /// <summary>
        /// Permission keys to assign to the user.
        /// </summary>
        /// <value>Permission keys to assign to the user.</value>
        [DataMember(Name = "permissions", EmitDefaultValue = false)]
        public List<string> Permissions { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AddOrganizationUsersRequestUsersInner {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Roles: ").Append(Roles).Append("\n");
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
