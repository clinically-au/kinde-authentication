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
    /// GetRedirectCallbackUrlsResponse
    /// </summary>
    [DataContract(Name = "get_redirect_callback_urls_response")]
    public partial class GetRedirectCallbackUrlsResponse : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GetRedirectCallbackUrlsResponse" /> class.
        /// </summary>
        /// <param name="redirectUrls">An application&#39;s redirect callback URLs..</param>
        public GetRedirectCallbackUrlsResponse(List<RedirectCallbackUrls> redirectUrls = default(List<RedirectCallbackUrls>))
        {
            this.RedirectUrls = redirectUrls;
        }

        /// <summary>
        /// An application&#39;s redirect callback URLs.
        /// </summary>
        /// <value>An application&#39;s redirect callback URLs.</value>
        [DataMember(Name = "redirect_urls", EmitDefaultValue = false)]
        public List<RedirectCallbackUrls> RedirectUrls { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class GetRedirectCallbackUrlsResponse {\n");
            sb.Append("  RedirectUrls: ").Append(RedirectUrls).Append("\n");
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
