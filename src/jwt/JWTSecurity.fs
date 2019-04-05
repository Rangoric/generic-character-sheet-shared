namespace Utilities.Jwt

open System.Linq
open System.Net.Http
open Microsoft.IdentityModel.Tokens
open Microsoft.IdentityModel.Protocols
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open System.Threading
open System.IdentityModel.Tokens.Jwt
open Newtonsoft.Json.Linq
open System.Net.Http.Headers
open System
open Microsoft.AspNetCore.Http
open System.Security.Claims

module JWTSecurity =
    let GetUserId (claimsPrincipal:ClaimsPrincipal) =
        let identity = claimsPrincipal.Identity :?> ClaimsIdentity
        let claims = identity.Claims.ToArray()
        let subjectClaim =
            claims 
            |> Array.filter (fun t -> t.Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
            |> Array.head
        let userID = subjectClaim.Value
        userID
    let Setup configurationUrl audience issuer metadata =
        let configuration =
            let documentRetriever = HttpDocumentRetriever();
            documentRetriever.RequireHttps <- true
            new ConfigurationManager<OpenIdConnectConfiguration>(
                configurationUrl,
                OpenIdConnectConfigurationRetriever(),
                documentRetriever)
        let validationParameter =
            let result = TokenValidationParameters()
            result.RequireSignedTokens <- true
            result.ValidAudience <- audience
            result.ValidateAudience <- true
            result.ValidIssuer <- issuer
            result.ValidateIssuer <- true
            result.ValidateIssuerSigningKey <- true
            result.ValidateLifetime <- true
            result.IssuerSigningKeys <- 
                (configuration.GetConfigurationAsync(CancellationToken.None)
                |> Async.AwaitTask
                |> Async.RunSynchronously).SigningKeys
            result       
        let getHeaderValue (request:HttpRequest) =
            let headerValue =
                match request.Headers.ContainsKey "Authorization" with
                | true ->
                    request.Headers.["Authorization"]
                | false ->
                    match request.Headers.ContainsKey "authorization" with
                    | true ->
                        request.Headers.["authorization"]
                    | false ->
                        raise (HttpRequestException "No Token")
            let splitHeader = headerValue.ToString().Split ' '
            AuthenticationHeaderValue(splitHeader.[0], splitHeader.[1])
        let rec authorize (request:HttpRequest) = 
            let header = getHeaderValue request
            match header with
            | null -> None
            | _ ->
                match header.Scheme with
                | "Bearer" ->
                    let handler = JwtSecurityTokenHandler()
                    try
                        let (claims, token) = handler.ValidateToken(header.Parameter, validationParameter)
                        let jwtToken = token :?> JwtSecurityToken
                        let profile = 
                            {
                                (jwtToken.Payload.[metadata] :?> JObject).ToObject<ActorProfile>() with
                                    Name = jwtToken.Payload.["name"] :?> string;
                                    ID = GetUserId claims
                            }
                        Some (profile)

                    with
                        | :? SecurityTokenSignatureKeyNotFoundException ->
                            configuration.RequestRefresh()
                            authorize request
                        | _ -> None
                | _ -> None
        authorize
    let SetupWithEnvironmentVariable:(HttpRequest -> Option<(ActorProfile)>) =
        Setup
            (Environment.GetEnvironmentVariable "Authorization-Configuration-Url")
            (Environment.GetEnvironmentVariable "Authorization-ClientID")
            (Environment.GetEnvironmentVariable "Authorization-Issuer")
            (Environment.GetEnvironmentVariable "Authorization-Metadata")
        
    let IsValid (request:HttpRequest) =
        let claimTokenTuple = SetupWithEnvironmentVariable request
        match claimTokenTuple with
        | Some (profile) ->
            (true, Some profile)
        | None ->
            (false, None)

    let IsValidInGroups (request:HttpRequest) (groups:string list) =
        let (isValid, profile) = IsValid request
        match isValid with
        | false -> (isValid, profile)
        | true ->
            match profile with
            | None -> (isValid, profile)
            | Some actorProfile ->
                match (Set.ofList groups) - (Set.ofList actorProfile.Roles) |> List.ofSeq with
                | [] -> (true, profile)
                | _ -> (false, None)
