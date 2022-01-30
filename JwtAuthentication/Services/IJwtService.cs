using JwtAuthentication.Models;
using System.Threading.Tasks;

namespace JwtAuthentication.Services
{
    public interface IJwtService
    {

        Task<string> GetTokenAsync(AuthRequest authRequest);
    }
}
