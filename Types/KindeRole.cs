using System.Text.Json.Serialization;
using Clinically.Kinde.Authentication.ManagementApi.Model;

namespace Clinically.Kinde.Authentication.Types;

public class KindeRole
{
    [JsonPropertyName("id")]
    public string Id { get; set; }
    [JsonPropertyName("name")]
    public string Name { get; set; }
    [JsonPropertyName("description")]
    public string? Description { get; set; }
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    public static KindeRole FromRoles(Roles role)
    {
        return new KindeRole()
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description,
            Key = role.Key
        };
    }
}