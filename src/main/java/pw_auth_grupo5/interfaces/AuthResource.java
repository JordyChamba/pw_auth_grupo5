package pw_auth_grupo5.interfaces;

import java.time.Instant;
import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.smallrye.jwt.build.Jwt;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @jakarta.inject.Inject
    pw_auth_grupo5.repository.UsuarioRepository repository;

    @ConfigProperty(name = "auth.issuer")
    String issuer;

    @ConfigProperty(name = "auth.token.ttl")
    Long ttl;

    @GET
    @Path("/token")
    public TokenResponse token(
            @QueryParam("user") String user,
            @QueryParam("password") String password) {

        String role;

        pw_auth_grupo5.Domain.Usuario usuario = repository.findByUsername(user);

        if (usuario != null && usuario.password.equals(password)) {
            role = "admin";
        } else {
            throw new jakarta.ws.rs.WebApplicationException(
                    jakarta.ws.rs.core.Response.Status.UNAUTHORIZED);
        }

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttl);

        String jwt = Jwt.issuer(issuer)
                .subject(user)
                .groups(Set.of(role))
                .issuedAt(now)
                .expiresAt(exp)
                .sign();

        return new TokenResponse(jwt, exp.getEpochSecond(), role);
    }

    public static class TokenResponse {

        public String accessToken;

        public long expiresAt;

        public String role;

        public TokenResponse() {
        }

        public TokenResponse(String accessToken, long expiresAt, String role) {

            this.accessToken = accessToken;

            this.expiresAt = expiresAt;

            this.role = role;

        }

    }

}
