/*
 * An example RADIUS backend for lunar, built with Spring Boot.
 *
 * This implements the lunar backend API (the same endpoints lunar_backend_sim
 * serves), but instead of mirroring attributes back it performs REAL
 * authentication and returns a single Framed-IP-Address. Point lunar's
 * subscriber.endpoint at this server and lunar will:
 *
 *   1. fetch the TEST virtual (one NAS client, secret "testing123"),
 *   2. forward each Access-Request here, where we authenticate test / test over
 *      PAP, CHAP, MS-CHAPv1 or MS-CHAPv2,
 *   3. reply Access-Accept with Framed-IP-Address = 192.168.50.50 (or reject).
 *
 * Accounting and CoA are acknowledged; the log and health endpoints are
 * accepted.
 *
 * Run it (from this directory) with "mvn spring-boot:run" and it listens on
 * 127.0.0.1:5555. See README.rst for the full walk-through.
 *
 * This is EXAMPLE code - a starting point to adapt, not a production backend.
 */
package io.interstellio.radius;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        // --nodebug (or RADIUS_BACKEND_NODEBUG) turns the per-exchange logging
        // off so only the startup line is printed; otherwise every exchange is
        // logged in full.
        boolean nodebug = System.getenv("RADIUS_BACKEND_NODEBUG") != null;
        for (String arg : args) {
            if (arg.equals("--nodebug")) {
                nodebug = true;
            }
        }
        BackendController.debug = !nodebug;

        SpringApplication application = new SpringApplication(Application.class);
        application.setBannerMode(org.springframework.boot.Banner.Mode.OFF);
        application.run(args);

        System.out.println("RADIUS backend listening on http://127.0.0.1:5555");
    }
}
