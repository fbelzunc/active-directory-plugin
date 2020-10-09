package hudson.plugins.active_directory;

import org.jvnet.localizer.Localizable;

/**
 * Classification of all possible TLS communication configurations
 *
 */
enum TlsCommunicationConfiguration {
    PLAIN_TEXT  (Messages._TlsCommunicationConfiguration_PlainText()),
    TLS          (Messages._TlsCommunicationConfiguration_Tls())
    ;

    public final Localizable msg;

    TlsCommunicationConfiguration(Localizable msg) {
        this.msg = msg;
    }

    public String getDisplayName() {
        return msg.toString();
    }
}
