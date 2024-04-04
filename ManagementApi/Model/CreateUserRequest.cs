/*
 * Kinde Management API
 *
 * Provides endpoints to manage your Kinde Businesses
 *
 * The version of the OpenAPI document: 1
 * Contact: support@kinde.com
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using FileParameter = Kinde.Api.Client.FileParameter;
using OpenAPIDateConverter = Kinde.Api.Client.OpenAPIDateConverter;

namespace Kinde.Api.Model
{
    /// <summary>
    /// CreateUserRequest
    /// </summary>
    [DataContract(Name = "createUser_request")]
    public partial class CreateUserRequest : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateUserRequest" /> class.
        /// </summary>
        /// <param name="profile">profile.</param>
        /// <param name="organizationCode">The unique code associated with the organization you want the user to join..</param>
        /// <param name="identities">Array of identities to assign to the created user.</param>
        public CreateUserRequest(CreateUserRequestProfile profile = default(CreateUserRequestProfile), string organizationCode = default(string), List<CreateUserRequestIdentitiesInner> identities = default(List<CreateUserRequestIdentitiesInner>))
        {
            this.Profile = profile;
            this.OrganizationCode = organizationCode;
            this.Identities = identities;
        }

        /// <summary>
        /// Gets or Sets Profile
        /// </summary>
        [DataMember(Name = "profile", EmitDefaultValue = false)]
        public CreateUserRequestProfile Profile { get; set; }

        /// <summary>
        /// The unique code associated with the organization you want the user to join.
        /// </summary>
        /// <value>The unique code associated with the organization you want the user to join.</value>
        [DataMember(Name = "organization_code", EmitDefaultValue = false)]
        public string OrganizationCode { get; set; }

        /// <summary>
        /// Array of identities to assign to the created user
        /// </summary>
        /// <value>Array of identities to assign to the created user</value>
        [DataMember(Name = "identities", EmitDefaultValue = false)]
        public List<CreateUserRequestIdentitiesInner> Identities { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class CreateUserRequest {\n");
            sb.Append("  Profile: ").Append(Profile).Append("\n");
            sb.Append("  OrganizationCode: ").Append(OrganizationCode).Append("\n");
            sb.Append("  Identities: ").Append(Identities).Append("\n");
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
