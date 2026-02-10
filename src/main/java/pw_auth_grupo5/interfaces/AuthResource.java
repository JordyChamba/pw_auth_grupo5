package pw_auth_grupo5.interfaces;

import io.smallrye.jwt.build.Jwt;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import pw_auth_grupo5.Domain.Usuario;

import java.time.Instant;

@Path("/auth")
public class AuthResource {

    @GET
    @Path("/token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(
            @QueryParam("user") String user,
            @QueryParam("password") String password) {

        Usuario usuarioEncontrado = Usuario.find("username", user).firstResult();

        if (usuarioEncontrado != null && usuarioEncontrado.password.equals(password)) {

            String issuer = "matricular-auth";
            long ttl = 3600;
            Instant now = Instant.now();
            Instant exp = now.plusSeconds(ttl);

            String jwt = Jwt.issuer(issuer)
                    .subject(user)
                    .issuedAt(now)
                    .expiresAt(exp)
                    .sign();
            return Response.ok(jwt).build();
        } else {
            return null;
        }
    }
}