package verification.registration;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import verification.appuser.AppUser;
import verification.appuser.AppUserRole;
import verification.appuser.AppUserService;
import verification.email.EmailSender;
import verification.registration.token.ConfirmationService;
import verification.registration.token.ConfirmationToken;

import javax.imageio.spi.RegisterableService;
import java.time.LocalDateTime;

@Service
public class RegistrationService {
    private final EmailValidator emailValidator;
    private final AppUserService appUserService;
    private final ConfirmationService confirmationService;
    private final EmailSender emailSender;

    public RegistrationService(EmailValidator emailValidator, AppUserService appUserService, ConfirmationService confirmationService, EmailSender emailSender) {
        this.emailValidator = emailValidator;
        this.appUserService = appUserService;
        this.confirmationService = confirmationService;
        this.emailSender = emailSender;
    }

    public String register(RegistrationRequest request){
        boolean isValidEmail = emailValidator
                .test(request.getEmail());

        if (!isValidEmail) {
            throw new IllegalStateException("email not valid");
        }
        String token =  appUserService.signUpUser(
                new AppUser (
                        request.getFirstName(),
                        request.getLastName(),
                        request.getEmail(),
                        request.getPassword(),
                        AppUserRole.USER
                )
        );

        String link = "http://localhost:8080/api/v1/registration/confirm?token=" + token;
        emailSender.send(
                request.getEmail(),
                buildEmail(request.getFirstName(), link));

        return token;
    }

    @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiredAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("token expired");
        }

        confirmationService.setConfirmedAt(token);
        appUserService.enableAppUser(
                confirmationToken.getAppUser().getEmail());
        return "confirmed";
    }


    private String buildEmail(String name, String link) {
        return "<div style=\\\"font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c\\\">\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"<span style=\\\"display:none;font-size:1px;color:#fff;max-height:0\\\"></span>\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"  <table role=\\\"presentation\\\" width=\\\"100%\\\" style=\\\"border-collapse:collapse;min-width:100%;width:100%!important\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\">\\n\" +\n" +
                "                \"    <tbody><tr>\\n\" +\n" +
                "                \"      <td width=\\\"100%\\\" height=\\\"53\\\" bgcolor=\\\"#0b0c0c\\\">\\n\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"        <table role=\\\"presentation\\\" width=\\\"100%\\\" style=\\\"border-collapse:collapse;max-width:580px\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\" align=\\\"center\\\">\\n\" +\n" +
                "                \"          <tbody><tr>\\n\" +\n" +
                "                \"            <td width=\\\"70\\\" bgcolor=\\\"#0b0c0c\\\" valign=\\\"middle\\\">\\n\" +\n" +
                "                \"                <table role=\\\"presentation\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\" style=\\\"border-collapse:collapse\\\">\\n\" +\n" +
                "                \"                  <tbody><tr>\\n\" +\n" +
                "                \"                    <td style=\\\"padding-left:10px\\\">\\n\" +\n" +
                "                \"                  \\n\" +\n" +
                "                \"                    </td>\\n\" +\n" +
                "                \"                    <td style=\\\"font-size:28px;line-height:1.315789474;Margin-top:4px;padding-left:10px\\\">\\n\" +\n" +
                "                \"                      <span style=\\\"font-family:Helvetica,Arial,sans-serif;font-weight:700;color:#ffffff;text-decoration:none;vertical-align:top;display:inline-block\\\">Confirm your email</span>\\n\" +\n" +
                "                \"                    </td>\\n\" +\n" +
                "                \"                  </tr>\\n\" +\n" +
                "                \"                </tbody></table>\\n\" +\n" +
                "                \"              </a>\\n\" +\n" +
                "                \"            </td>\\n\" +\n" +
                "                \"          </tr>\\n\" +\n" +
                "                \"        </tbody></table>\\n\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"      </td>\\n\" +\n" +
                "                \"    </tr>\\n\" +\n" +
                "                \"  </tbody></table>\\n\" +\n" +
                "                \"  <table role=\\\"presentation\\\" class=\\\"m_-6186904992287805515content\\\" align=\\\"center\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\" style=\\\"border-collapse:collapse;max-width:580px;width:100%!important\\\" width=\\\"100%\\\">\\n\" +\n" +
                "                \"    <tbody><tr>\\n\" +\n" +
                "                \"      <td width=\\\"10\\\" height=\\\"10\\\" valign=\\\"middle\\\"></td>\\n\" +\n" +
                "                \"      <td>\\n\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"                <table role=\\\"presentation\\\" width=\\\"100%\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\" style=\\\"border-collapse:collapse\\\">\\n\" +\n" +
                "                \"                  <tbody><tr>\\n\" +\n" +
                "                \"                    <td bgcolor=\\\"#1D70B8\\\" width=\\\"100%\\\" height=\\\"10\\\"></td>\\n\" +\n" +
                "                \"                  </tr>\\n\" +\n" +
                "                \"                </tbody></table>\\n\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"      </td>\\n\" +\n" +
                "                \"      <td width=\\\"10\\\" valign=\\\"middle\\\" height=\\\"10\\\"></td>\\n\" +\n" +
                "                \"    </tr>\\n\" +\n" +
                "                \"  </tbody></table>\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"  <table role=\\\"presentation\\\" class=\\\"m_-6186904992287805515content\\\" align=\\\"center\\\" cellpadding=\\\"0\\\" cellspacing=\\\"0\\\" border=\\\"0\\\" style=\\\"border-collapse:collapse;max-width:580px;width:100%!important\\\" width=\\\"100%\\\">\\n\" +\n" +
                "                \"    <tbody><tr>\\n\" +\n" +
                "                \"      <td height=\\\"30\\\"><br></td>\\n\" +\n" +
                "                \"    </tr>\\n\" +\n" +
                "                \"    <tr>\\n\" +\n" +
                "                \"      <td width=\\\"10\\\" valign=\\\"middle\\\"><br></td>\\n\" +\n" +
                "                \"      <td style=\\\"font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px\\\">\\n\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"            <p style=\\\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\\\">Hi \" + name + \",</p><p style=\\\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\\\"> Thank you for registering. Please click on the below link to activate your account: </p><blockquote style=\\\"Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px\\\"><p style=\\\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\\\"> <a href=\\\"\" + link + \"\\\">Activate Now</a> </p></blockquote>\\n Link will expire in 15 minutes. <p>See you soon</p>\" +\n" +
                "                \"        \\n\" +\n" +
                "                \"      </td>\\n\" +\n" +
                "                \"      <td width=\\\"10\\\" valign=\\\"middle\\\"><br></td>\\n\" +\n" +
                "                \"    </tr>\\n\" +\n" +
                "                \"    <tr>\\n\" +\n" +
                "                \"      <td height=\\\"30\\\"><br></td>\\n\" +\n" +
                "                \"    </tr>\\n\" +\n" +
                "                \"  </tbody></table><div class=\\\"yj6qo\\\"></div><div class=\\\"adL\\\">\\n\" +\n" +
                "                \"\\n\" +\n" +
                "                \"</div></div>";
    }
}
