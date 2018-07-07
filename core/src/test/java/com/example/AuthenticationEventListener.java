package com.example;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventListener implements ApplicationListener<AbstractAuthenticationEvent> {

	private List<ApplicationEvent> receivedEvents = new ArrayList<>();

	@Override
	public void onApplicationEvent(AbstractAuthenticationEvent event) {
		receivedEvents.add(event);
	}

	public List<ApplicationEvent> getReceivedEvents() {
		return Collections.unmodifiableList(this.receivedEvents);
	}

	public void clear() {
		this.receivedEvents.clear();
	}
}
