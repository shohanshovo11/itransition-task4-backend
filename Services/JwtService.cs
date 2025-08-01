using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using backend.Models;

namespace backend.Services
{
  public interface IJwtService
  {
    string GenerateToken(User user);
    ClaimsPrincipal? ValidateToken(string token);
  }

  public class JwtService : IJwtService
  {
    private readonly IConfiguration _configuration;

    public JwtService(IConfiguration configuration)
    {
      _configuration = configuration;
    }

    public string GenerateToken(User user)
    {
      var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
      var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

      var claims = new[]
      {
          new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
          new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
          new Claim(JwtRegisteredClaimNames.Email, user.Email),
          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
      };

      var token = new JwtSecurityToken(
          issuer: _configuration["Jwt:Issuer"],
          audience: _configuration["Jwt:Audience"],
          claims: claims,
          expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpirationMinutes"])),
          signingCredentials: credentials
      );

      return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
      var tokenHandler = new JwtSecurityTokenHandler();
      var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);

      try
      {
        var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = new SymmetricSecurityKey(key),
          ValidateIssuer = true,
          ValidIssuer = _configuration["Jwt:Issuer"],
          ValidateAudience = true,
          ValidAudience = _configuration["Jwt:Audience"],
          ClockSkew = TimeSpan.Zero
        }, out SecurityToken validatedToken);

        return principal;
      }
      catch
      {
        return null;
      }
    }
  }
}
