using System.Text.Json.Serialization;

namespace Clinically.Kinde.Authentication.Types;

public class KindeOrganization
{
    [JsonPropertyName("id")] public string Id { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; }
}