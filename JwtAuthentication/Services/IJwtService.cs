using JwtAuthentication.Models;
using System.Threading.Tasks;

namespace JwtAuthentication.Services
{
    public interface IJwtService
    {

        Task<AuthResponse> GetTokenAsync(AuthRequest authRequest,string ipAddress);
        Task<AuthResponse> GetRefreshTokenAsync(string idAddress,int userId,string userName);

        Task<bool> IsTokenValid(string accessToken,string ipAddress);
    }
}
