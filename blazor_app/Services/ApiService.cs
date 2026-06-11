using System.Net.Http.Headers;

namespace BlazorApp2.Services
{
    public class ApiService
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _config;

        public ApiService(HttpClient http, IConfiguration config)
        {
            _http = http;
            _config = config;
        }

        public async Task<bool> DeleteUserAsync(string userId, string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Delete,
                $"{_config["ApiSettings:BaseUrl"]}/users/{userId}");
            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            var response = await _http.SendAsync(request);
            return response.IsSuccessStatusCode;
        }

        public async Task<string> WhoAmIAsync(string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get,
                $"{_config["ApiSettings:BaseUrl"]}/whoami");
            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            var response = await _http.SendAsync(request);
            return await response.Content.ReadAsStringAsync();
        }
    }
}
