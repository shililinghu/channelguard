from __future__ import annotations
import copy
import time
from .storage import new_channel
from .monitor import observe,environment_patch


def initialize(store,engines,info,options):
    from .presets import candidates
    available=candidates(info)
    selections=[('direct','wifi',options['direct'])]
    if options.get('vpn'):selections.append(('vpn','vpn',options['vpn']))
    chosen=[]
    for role,kind,interface in selections:
        if not any(c['interface']==interface and c['discovery']['kind']==kind
                   and c['discovery']['readiness']=='ready' for c in available):
            raise ValueError('所选出口未就绪，请重新扫描。')
        existing=next((c for c in store.data['channels'] if c.get('network_role')==role),None)
        if existing is None:
            existing=next((c for c in store.data['channels'] if c.get('discovery',{}).get('kind')==kind
                           and c.get('interface')==interface),None)
        c=copy.deepcopy(existing) if existing else new_channel('出口 A · 本机 Wi-Fi 直连' if role=='direct' else '出口 B · VPN')
        c.update(interface=interface,node=None,network_role=role,environment_auto=bool(options.get('environment_auto',True)))
        c['discovery']=dict(c.get('discovery',{}),kind=kind,managed=False,readiness='ready')
        if role=='direct':c.update(doh=options['doh'],bootstrap_doh=options['doh'])
        chosen.append((existing,c))
    # Validate all selections before changing any live engine / saved configuration.
    from .config import validate_channel
    for _,c in chosen:validate_channel(c)
    for _,c in chosen:
        runtime=engines.active.get(c['id'])
        if runtime and any(p.poll() is None for p in runtime['browsers']):
            raise ValueError('请先关闭所选信道的专用浏览器，再初始化环境。')
    store.backup(store.root/('before-initialization-'+str(time.time_ns())+'.dpapi'))
    results=[]
    for existing,c in chosen:
        runtime=engines.active.get(c['id'])
        if runtime:
            engines.rebind(c)
        else:engines.start(c)
        observation=observe(engines.proxy(c['id']))
        c['external_vpn_pending']=not observation['reachable'] if c['network_role']=='direct' else False
        if c['environment_auto']:c.update(environment_patch(observation))
        c.pop('suggested_environment',None);c['monitor_paused']=False
        c['last_observation']=dict(observation,at=time.time())
        c['discovery']['environment_source']='已检测真实出口并校准环境' if observation['reachable'] else '出口检测失败；未使用系统直连后备'
        if existing:existing.update(c)
        else:store.data['channels'].append(c)
        engines.active[c['id']]['channel']=copy.deepcopy(c)
        engines.write_browser_manifest(c,engines.active[c['id']])
        results.append({'id':c['id'],'name':c['name'],'observation':observation})
    store.data['monitor']={'enabled':bool(options.get('monitor',True)),
                           'interval_seconds':30,'exit_interval_seconds':300}
    store.data['initialization']={'completed':True,'channel_ids':[c['id'] for _,c in chosen],
                                   'auto_start':True,'completed_at':time.time()}
    store.save()
    return results
