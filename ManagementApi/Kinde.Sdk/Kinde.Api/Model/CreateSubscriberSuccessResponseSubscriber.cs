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
    /// CreateSubscriberSuccessResponseSubscriber
    /// </summary>
    [DataContract(Name = "create_subscriber_success_response_subscriber")]
    public partial class CreateSubscriberSuccessResponseSubscriber : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateSubscriberSuccessResponseSubscriber" /> class.
        /// </summary>
        /// <param name="subscriberId">A unique identifier for the subscriber..</param>
        public CreateSubscriberSuccessResponseSubscriber(string subscriberId = default(string))
        {
            this.SubscriberId = subscriberId;
        }

        /// <summary>
        /// A unique identifier for the subscriber.
        /// </summary>
        /// <value>A unique identifier for the subscriber.</value>
        [DataMember(Name = "subscriber_id", EmitDefaultValue = false)]
        public string SubscriberId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class CreateSubscriberSuccessResponseSubscriber {\n");
            sb.Append("  SubscriberId: ").Append(SubscriberId).Append("\n");
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
