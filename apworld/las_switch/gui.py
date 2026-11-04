"""LAS tabs hosted by the Archipelago client shipped inside this .apworld."""
from kvui import GameManager
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from .client_model import snapshot

def text_panel():
    scroll=ScrollView(do_scroll_x=False)
    label=Label(text='',markup=False,halign='left',valign='top',size_hint_y=None,padding=(dp(12),dp(10)))
    label.bind(width=lambda widget,value:setattr(widget,'text_size',(max(1,value-dp(24)),None)))
    label.bind(texture_size=lambda widget,value:setattr(widget,'height',value[1]+dp(20)))
    scroll.add_widget(label)
    return scroll,label

class LASManager(GameManager):
    base_title="Link's Awakening — Archipelago"

    def build(self):
        root=super().build()
        status,self.status_label=text_panel()
        self.add_client_tab('LAS Status',status)
        history,self.history_label=text_panel()
        history_box=BoxLayout(orientation='vertical')
        options=BoxLayout(size_hint_y=None,height=dp(38))
        checkbox=CheckBox(active=self.ctx.sent_notifications,size_hint_x=None,width=dp(40))
        checkbox.bind(active=lambda widget,value:setattr(self.ctx,'sent_notifications',value))
        options.add_widget(checkbox);options.add_widget(Label(text='Show items sent to other players',halign='left'))
        history_box.add_widget(options);history_box.add_widget(history)
        self.add_client_tab('Item History',history_box)
        tracker_box=BoxLayout(orientation='vertical')
        filters=BoxLayout(size_hint_y=None,height=dp(40))
        self.search=TextInput(hint_text='Search checks',multiline=False)
        self.tracker_filter=Spinner(text='Remaining',values=('Remaining','In logic','Checked','All'),size_hint_x=.4)
        filters.add_widget(self.search);filters.add_widget(self.tracker_filter)
        tracker,self.tracker_label=text_panel()
        tracker_box.add_widget(filters);tracker_box.add_widget(tracker)
        self.add_client_tab('LAS Tracker',tracker_box)
        # The inherited Hints tab uses AP's real hint requests, points and
        # priorities. Do not build a separate spoiler-based hint service.
        controls=BoxLayout(size_hint_y=None,height=dp(40))
        self.hint_selector=Spinner(text='Choose a received hint',values=(),size_hint_x=.7)
        self.show_hint=Button(text='Show hint in game',size_hint_x=.3,disabled=True)
        self._hint_lookup={}
        self.show_hint.bind(on_release=lambda widget:self.ctx.request_game_hint(self._hint_lookup.get(self.hint_selector.text)))
        controls.add_widget(self.hint_selector);controls.add_widget(self.show_hint)
        self.log_panels['Hints'].add_widget(controls)
        self._las_timer=Clock.schedule_interval(self.refresh_las,0.5)
        self.refresh_las(0)
        return root

    def refresh_las(self,dt):
        model=snapshot(self.ctx)
        pending=str(model['pending']) if model['pending'] is not None else 'Waiting for validated history'
        self.status_label.text=(f"Room: {model['room']}\nGame: {model['game']}\n\n"
                                f"Items waiting: {pending}\nChecks: {model['checked']} / {model['total']}\n"
                                f"Checks waiting to upload: {model['local_pending_checks']}\n"
                                f"DeathLink: {'On' if model['deathlink'] else 'Off'}\n\n"
                                f"{model['error'] or ''}")
        if self.ctx.pending_hint:self.status_label.text+='\nHint waiting for the game.'
        if self.ctx.sent_notifications and self.ctx.outgoing_history:self.status_label.text+='\nLatest sent: '+self.ctx.outgoing_history[-1]['text']
        hints=self.ctx.available_game_hints()
        self._hint_lookup={str(r['index']+1)+'. '+r['text']:r['index'] for r in hints}
        values=tuple(self._hint_lookup)
        if tuple(self.hint_selector.values)!=values:self.hint_selector.values=values
        if self.hint_selector.text not in self._hint_lookup:self.hint_selector.text='Choose a received hint'
        self.show_hint.disabled=not self._hint_lookup or not self.ctx.bridge.hello or self.ctx.bridge.hello.get('supports_hints') is not True
        lines=[f"{'Delivered' if row['delivered'] else 'Waiting'} · {row['item']} · From {row['sender']}" for row in model['history']]
        if self.ctx.sent_notifications:
            lines+=['','Items sent:']+[row['text'] for row in reversed(self.ctx.outgoing_history[-25:])]
        self.history_label.text='\n'.join(lines) or 'No received items yet.'
        query=self.search.text.casefold().strip();mode=self.tracker_filter.text
        rows=[r for r in model['tracker'] if query in (r['location']+' '+r['category']).casefold()]
        rows=[r for r in rows if mode=='All' or (mode=='Checked' and r['checked']) or
              (mode=='Remaining' and not r['checked']) or (mode=='In logic' and r['reachable'] and not r['checked'])]
        self.tracker_label.text='\n'.join(f"{'Checked' if r['checked'] else 'In logic' if r['reachable'] else 'Later'} · {r['location']} ({r['category']})" for r in rows) or 'No checks match this filter.'

    def on_stop(self):
        if hasattr(self,'_las_timer'):self._las_timer.cancel()
        return super().on_stop()
