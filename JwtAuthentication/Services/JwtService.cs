using JwtAuthentication.Context;
using JwtAuthentication.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication.Services
{
    public class JwtService : IJwtService
    {

        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public JwtService(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<string> GetTokenAsync(AuthRequest authRequest)
        {
           var user= _context.Users.FirstOrDefault(x=>x.UserName.Equals(authRequest.UserName) && x.Password.Equals(authRequest.Password));
            if(user == null)
                return await Task.FromResult<string>(null);

            var jwtKey = _configuration.GetValue<string>("JwtSettings:Key");
            var keyBytes= Encoding.ASCII.GetBytes(jwtKey);

            var tokenHandler = new JwtSecurityTokenHandler();
            var descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserName),
                }),
                Expires=DateTime.UtcNow.AddSeconds(60),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes),SecurityAlgorithms.HmacSha256)

            };

            var token=tokenHandler.CreateToken(descriptor);

            return await Task.FromResult(tokenHandler.WriteToken(token));
        }
    }
}
