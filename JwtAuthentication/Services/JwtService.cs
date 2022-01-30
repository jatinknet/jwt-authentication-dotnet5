using JwtAuthentication.Context;
using JwtAuthentication.Entities;
using JwtAuthentication.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
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

        public async Task<AuthResponse> GetRefreshTokenAsync(string ipAddress, int userId, string userName)
        {
            var refreshToken = GenerateRefreshToken();
            var accessToken=GenerateToken(userName);
            return await SaveTokenDetails(ipAddress, userId, accessToken, refreshToken);
        }

        public async Task<AuthResponse> GetTokenAsync(AuthRequest authRequest,string ipAddress)
        {
            var user = _context.Users.FirstOrDefault(x => x.UserName.Equals(authRequest.UserName) && x.Password.Equals(authRequest.Password));
            if (user == null)
                return await Task.FromResult<AuthResponse>(null);

            string tokenString = GenerateToken(user.UserName);
            string refreshToken = GenerateRefreshToken();
            await SaveTokenDetails(ipAddress, user.UserId, tokenString, refreshToken);

            return new AuthResponse
            {
                Token = tokenString,
                RefreshToken = refreshToken,
            };
        }

        private async Task<AuthResponse> SaveTokenDetails(string ipAddress, int userId, string tokenString, string refreshToken)
        {
            var userRefreshToken = new UserRefreshToken
            {
                CreatedDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddMinutes(5),
                IpAddress = ipAddress,
                IsInvalidated = false,
                RefreshToken = refreshToken,
                Token = tokenString,
                UserId = userId
            };

            await _context.UserRefreshTokens.AddAsync(userRefreshToken);
            await _context.SaveChangesAsync();

            return new AuthResponse { Token = tokenString, RefreshToken = refreshToken,IsSuccess=true };
        }

        private string GenerateRefreshToken()
        {
            var byteArray=new byte[64];

            using (var cryptoProvider= new RNGCryptoServiceProvider())
            {
                cryptoProvider.GetBytes(byteArray);
                return Convert.ToBase64String(byteArray);
            }
        }

        private string GenerateToken(string userName)
        {
            var jwtKey = _configuration.GetValue<string>("JwtSettings:Key");
            var keyBytes = Encoding.ASCII.GetBytes(jwtKey);

            var tokenHandler = new JwtSecurityTokenHandler();
            var descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userName),
                }),
                Expires = DateTime.UtcNow.AddSeconds(90),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256)

            };

            var token = tokenHandler.CreateToken(descriptor);

            string tokenString = tokenHandler.WriteToken(token);
            return tokenString;
        }

        public async Task<bool> IsTokenValid(string accessToken, string ipAddress)
        {
            var isValid = _context.UserRefreshTokens.FirstOrDefault(x => x.Token == accessToken
           && x.IpAddress == ipAddress) != null;
            return await Task.FromResult(isValid);
        }
    }
}
